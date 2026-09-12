import { useEffect, useRef, useState } from "react";
import ForceGraph3D from "3d-force-graph";
import * as THREE from "three";
import { useTheme } from "../context/ThemeContext";
import { graphData as fallbackGraphData } from "../data/mockData";
import api from "../api/client";

const COLORS = {
  apk: "#00d4aa",
  sample: "#00d4aa",
  campaign: "#ff4d6a",
  certificate: "#ffb020",
  domain: "#3b9eff",
  package: "#a78bfa",
};

const SIZES = {
  apk: 4.2,
  sample: 4.2,
  campaign: 7.5,
  certificate: 3.5,
  domain: 3.0,
  package: 3.2,
};

function makeLabelSprite(text, theme) {
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  const fontSize = 26;
  ctx.font = `600 ${fontSize}px DM Sans, sans-serif`;
  const paddingX = 14;
  const paddingY = 8;
  const metrics = ctx.measureText(text);
  const width = Math.ceil(metrics.width + paddingX * 2);
  const height = fontSize + paddingY * 2;
  canvas.width = width;
  canvas.height = height;

  ctx.font = `600 ${fontSize}px DM Sans, sans-serif`;
  ctx.fillStyle = theme === "light" ? "rgba(255,255,255,0.88)" : "rgba(6,10,16,0.78)";
  const radius = 8;
  ctx.beginPath();
  ctx.moveTo(radius, 0);
  ctx.arcTo(width, 0, width, height, radius);
  ctx.arcTo(width, height, 0, height, radius);
  ctx.arcTo(0, height, 0, 0, radius);
  ctx.arcTo(0, 0, width, 0, radius);
  ctx.closePath();
  ctx.fill();

  ctx.fillStyle = theme === "light" ? "#0f1b2d" : "#e9eef7";
  ctx.textBaseline = "middle";
  ctx.textAlign = "center";
  ctx.fillText(text, width / 2, height / 2);

  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  const material = new THREE.SpriteMaterial({
    map: texture,
    transparent: true,
    depthWrite: false,
  });
  const sprite = new THREE.Sprite(material);
  const scale = 0.18;
  sprite.scale.set(width * scale, height * scale, 1);
  return sprite;
}

export default function RelationshipGraph({
  height = "520px",
  filter = "all",
  onNodeSelect,
  graphData: customData,
  campaignId,
}) {
  const containerRef = useRef(null);
  const graphRef = useRef(null);
  const highlightRef = useRef({ node: null, links: new Set(), neighbors: new Set() });
  const { theme } = useTheme();
  const [activeData, setActiveData] = useState(customData || null);

  useEffect(() => {
    if (customData) {
      setActiveData(customData);
      return;
    }

    if (campaignId) {
      api.getCampaignGraph(campaignId)
        .then((backendGraph) => {
          if (backendGraph?.nodes) {
            const mappedNodes = backendGraph.nodes.map((n) => ({
              id: n.id,
              label: n.label,
              group: n.type === "sample" ? "apk" : n.type,
              title: `${n.type}: ${n.label}`,
              rawId: n.id.replace(/^(sample_|camp_|cert_)/, ""),
              metadata: n.metadata,
            }));
            const mappedEdges = (backendGraph.edges || []).map((e, idx) => ({
              id: `e-${idx}`,
              from: e.source,
              to: e.target,
              label: e.relationship || "relates",
            }));
            setActiveData({ nodes: mappedNodes, edges: mappedEdges });
          } else {
            setActiveData(fallbackGraphData);
          }
        })
        .catch((err) => {
          console.error("Failed to load campaign graph:", err);
          setActiveData(fallbackGraphData);
        });
    } else {
      setActiveData(fallbackGraphData);
    }
  }, [campaignId, customData]);

  useEffect(() => {
    if (!containerRef.current || !activeData) return;

    const currentGraphData = activeData;
    const filteredNodes = (currentGraphData.nodes || []).filter(
      (n) => filter === "all" || n.group === filter
    );
    const ids = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = (currentGraphData.edges || []).filter(
      (e) => ids.has(e.from) && ids.has(e.to)
    );

    const nodes = filteredNodes.map((n) => ({
      id: n.id,
      label: n.label,
      group: n.group,
      title: n.title,
      rawId: n.rawId,
    }));

    const links = filteredEdges.map((e, i) => ({
      id: `e-${i}`,
      source: e.from,
      target: e.to,
      label: e.label,
    }));

    const bg = theme === "light" ? "#eef3f9" : "#060a10";
    const linkColor = theme === "light" ? "rgba(75, 93, 120, 0.55)" : "rgba(139, 155, 180, 0.45)";

    if (graphRef.current) {
      graphRef.current._destructor?.();
      graphRef.current = null;
      containerRef.current.innerHTML = "";
    }

    const graph = ForceGraph3D()(containerRef.current)
      .backgroundColor(bg)
      .graphData({ nodes, links })
      .nodeId("id")
      .nodeLabel((n) => `${n.label}\n(${n.group})`)
      .nodeRelSize(6)
      .linkWidth((l) => (highlightRef.current.links.has(l) ? 2.2 : 0.9))
      .linkOpacity(0.75)
      .linkColor((l) => (highlightRef.current.links.has(l) ? "#00d4aa" : linkColor))
      .linkDirectionalParticles((l) => (highlightRef.current.links.has(l) ? 3 : 0))
      .linkDirectionalParticleWidth(1.6)
      .linkDirectionalParticleSpeed(0.006)
      .showNavInfo(false)
      .enableNodeDrag(true)
      .nodeThreeObject((node) => {
        const group = new THREE.Group();
        const radius = SIZES[node.group] || 4.5;
        const color = COLORS[node.group] || COLORS.apk;

        const sphere = new THREE.Mesh(
          new THREE.SphereGeometry(radius, 32, 32),
          new THREE.MeshStandardMaterial({
            color,
            metalness: 0.35,
            roughness: 0.28,
            emissive: color,
            emissiveIntensity: 0.22,
          })
        );
        group.add(sphere);

        const glow = new THREE.Mesh(
          new THREE.SphereGeometry(radius * 1.18, 20, 20),
          new THREE.MeshBasicMaterial({
            color,
            transparent: true,
            opacity: 0.16,
            depthWrite: false,
          })
        );
        group.add(glow);

        const label = makeLabelSprite(node.label, theme);
        label.position.y = radius + 5;
        group.add(label);

        return group;
      })
      .onNodeClick((node) => {
        if (!node) {
          highlightRef.current = { node: null, links: new Set(), neighbors: new Set() };
          if (onNodeSelect) onNodeSelect(null);
          updateHighlights();
          return;
        }

        const neighbors = new Set();
        const linksSet = new Set();
        links.forEach((l) => {
          const src = typeof l.source === "object" ? l.source.id : l.source;
          const tgt = typeof l.target === "object" ? l.target.id : l.target;
          if (src === node.id || tgt === node.id) {
            linksSet.add(l);
            neighbors.add(src);
            neighbors.add(tgt);
          }
        });
        highlightRef.current = { node, links: linksSet, neighbors };
        if (onNodeSelect) {
          onNodeSelect({
            id: node.id,
            rawId: node.rawId,
            label: node.label,
            group: node.group,
            title: node.title,
          });
        }
        updateHighlights();
      })
      .onBackgroundClick(() => {
        highlightRef.current = { node: null, links: new Set(), neighbors: new Set() };
        if (onNodeSelect) onNodeSelect(null);
        updateHighlights();
      })
      .onNodeHover((node) => {
        if (containerRef.current) {
          containerRef.current.style.cursor = node ? "pointer" : "grab";
        }
        const controls = graph.controls();
        if (controls) {
          controls.autoRotate = true;
          controls.autoRotateSpeed = node ? 2.4 : 1.1;
        }
      });

    function updateHighlights() {
      graph
        .linkWidth((l) => (highlightRef.current.links.has(l) ? 2.2 : 0.9))
        .linkColor((l) => (highlightRef.current.links.has(l) ? "#00d4aa" : linkColor))
        .linkDirectionalParticles((l) => (highlightRef.current.links.has(l) ? 3 : 0));
    }

    const scene = graph.scene();
    scene.add(new THREE.AmbientLight(0xffffff, 0.7));
    const key = new THREE.DirectionalLight(0xffffff, 0.95);
    key.position.set(40, 60, 30);
    scene.add(key);
    const fill = new THREE.DirectionalLight(0x88ccff, 0.35);
    fill.position.set(-40, -20, -30);
    scene.add(fill);

    const controls = graph.controls();
    if (controls) {
      controls.autoRotate = false;
      controls.autoRotateSpeed = 1.1;
      controls.enableDamping = true;
      controls.dampingFactor = 0.06;
    }

    const el = containerRef.current;
    const onEnter = () => {
      const c = graph.controls();
      if (c) {
        c.autoRotate = true;
        c.autoRotateSpeed = 1.1;
      }
    };
    const onLeave = () => {
      const c = graph.controls();
      if (c) c.autoRotate = false;
    };

    el.addEventListener("mouseenter", onEnter);
    el.addEventListener("mouseleave", onLeave);

    graph.cameraPosition({ x: 0, y: 40, z: 180 });
    const fitTimer = setTimeout(() => graph.zoomToFit(600, 50), 900);

    graphRef.current = graph;

    const resize = () => {
      if (!containerRef.current || !graphRef.current) return;
      const { clientWidth, clientHeight } = containerRef.current;
      graphRef.current.width(clientWidth);
      graphRef.current.height(clientHeight);
    };
    resize();
    window.addEventListener("resize", resize);

    return () => {
      clearTimeout(fitTimer);
      window.removeEventListener("resize", resize);
      el.removeEventListener("mouseenter", onEnter);
      el.removeEventListener("mouseleave", onLeave);
      graph._destructor?.();
      graphRef.current = null;
      if (containerRef.current) containerRef.current.innerHTML = "";
    };
  }, [activeData, filter, onNodeSelect, theme]);

  return (
    <div
      ref={containerRef}
      style={{
        height,
        width: "100%",
        background: "var(--graph-bg)",
        borderRadius: "var(--radius-lg)",
        border: "1px solid var(--border)",
        overflow: "hidden",
        cursor: "grab",
      }}
    />
  );
}
