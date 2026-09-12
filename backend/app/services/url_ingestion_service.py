import os
import aiofiles
import uuid
import httpx
import socket
import ipaddress
import urllib.parse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import Sample
from app.services.upload_service import _process_local_file
from app.core.exceptions import CiphRException
from app.core.logging import logger

def validate_url_safe(url: str):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise CiphRException("INVALID_SCHEME", f"Unsupported scheme: {parsed.scheme}")
    
    hostname = parsed.hostname
    if not hostname:
        raise CiphRException("INVALID_URL", "URL missing hostname")
        
    try:
        addr_info = socket.getaddrinfo(hostname, 80)
    except socket.gaierror:
        raise CiphRException("DNS_FAILURE", f"Could not resolve hostname: {hostname}")
        
    for res in addr_info:
        ip = res[4][0]
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
            raise CiphRException("BLOCKED_DESTINATION", f"Resolved IP {ip} is not permitted")

async def process_url(url: str, submitted_by: str, db: AsyncSession) -> Sample:
    logger.info(f"Starting URL ingestion for {url}")
    validate_url_safe(url)
    
    parsed = urllib.parse.urlparse(url)
    filename = parsed.path.split('/')[-1]
    if not filename or '?' in filename:
        filename = "downloaded.apk"
        
    temp_id = str(uuid.uuid4())
    temp_filename = f"{temp_id}_{filename}"
    temp_filepath = os.path.join(settings.UPLOAD_DIR, temp_filename)
    
    size = 0
    current_url = url
    redirect_count = 0
    
    try:
        async with httpx.AsyncClient(timeout=settings.URL_FETCH_TIMEOUT) as client:
            while redirect_count <= settings.URL_MAX_REDIRECTS:
                # Pre-flight DNS validation for current_url
                validate_url_safe(current_url)
                
                # Stream the response
                async with client.stream('GET', current_url, follow_redirects=False) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location")
                        if not location:
                            raise CiphRException("INVALID_URL", "Redirect missing Location header")
                        
                        # Handle relative redirects
                        current_url = urllib.parse.urljoin(current_url, location)
                        redirect_count += 1
                        continue
                        
                    if response.status_code != 200:
                        raise CiphRException("CONNECTION_FAILURE", f"HTTP {response.status_code} returned")
                        
                    content_type = response.headers.get("Content-Type", "")
                    if "text/html" in content_type.lower() or "text/plain" in content_type.lower():
                        raise CiphRException("INVALID_CONTENT", "Response indicates text/html or plain text, not an APK")
                        
                    async with aiofiles.open(temp_filepath, 'wb') as out_file:
                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            size += len(chunk)
                            if size > settings.MAX_APK_SIZE_BYTES:
                                raise CiphRException("FILE_TOO_LARGE", f"File exceeds maximum size of {settings.MAX_APK_SIZE_MB}MB.")
                            await out_file.write(chunk)
                    
                    break
            
            if redirect_count > settings.URL_MAX_REDIRECTS:
                raise CiphRException("TOO_MANY_REDIRECTS", f"Exceeded maximum redirects ({settings.URL_MAX_REDIRECTS})")
                
        # Store using shared logic
        source_str = f"url|{url}"
        sample = await _process_local_file(temp_filepath, filename, size, source_str, submitted_by, db)
        return sample
        
    except httpx.TimeoutException:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise CiphRException("TIMEOUT", "Connection to URL timed out")
    except httpx.RequestError as e:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise CiphRException("CONNECTION_FAILURE", f"Network error during fetch: {e}")
    except CiphRException:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise
    except Exception as e:
        logger.error(f"Error during URL fetching: {e}")
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise CiphRException("URL_FETCH_FAILED", "An unexpected error occurred during URL fetching", status_code=500)
