const API_BASE = import.meta.env.VITE_CIPHR_API_BASE_URL || '/api/v1';

export class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
  const apiKey = import.meta.env.VITE_CIPHR_API_KEY || '';

  const headers = {
    ...options.headers,
  };

  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }

  if (!(options.body instanceof FormData) && !headers['Content-Type'] && options.body) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorData = null;
    let message = `Request failed with status ${response.status}`;
    try {
      errorData = await response.json();
      if (errorData?.detail) {
        message = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
      }
    } catch {
      // ignore json parse error on non-json error responses
    }
    throw new ApiError(message, response.status, errorData);
  }

  if (response.status === 204) {
    return null;
  }

  return response.json();
}

export const api = {
  // Samples
  uploadSample: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return request('/samples/upload', {
      method: 'POST',
      body: formData,
    });
  },

  getSampleStatus: (sampleId) => request(`/samples/${sampleId}/status`),
  getSample: (sampleId) => request(`/samples/${sampleId}`),
  getSampleAnalysis: (sampleId) => request(`/samples/${sampleId}/analysis`),
  getSampleFindings: (sampleId) => request(`/samples/${sampleId}/findings`),
  getRelatedSamples: (sampleId) => request(`/samples/${sampleId}/related`),
  listSamples: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/samples${query ? `?${query}` : ''}`);
  },

  // Campaigns
  listCampaigns: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/campaigns${query ? `?${query}` : ''}`);
  },
  getCampaign: (campaignId) => request(`/campaigns/${campaignId}`),
  getCampaignSamples: (campaignId) => request(`/campaigns/${campaignId}/samples`),
  getCampaignTimeline: (campaignId) => request(`/campaigns/${campaignId}/timeline`),
  getCampaignGraph: (campaignId) => request(`/campaigns/${campaignId}/graph`),
};

export default api;
