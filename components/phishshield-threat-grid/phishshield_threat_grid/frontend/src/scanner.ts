const instances = new WeakMap<object, {root: HTMLElement; cleanup: () => void}>();

// SVG geometry rotates with requestAnimationFrame, independently of CSS and SMIL.
export function renderScanner(parent: Element | ShadowRoot) {
  const previous = instances.get(parent);
  if (previous?.root.isConnected && parent.contains(previous.root)) {
    parent.querySelectorAll('.ps-security-art').forEach(node => {
      if (node !== previous.root) node.remove();
    });
    return previous.cleanup;
  }
  previous?.cleanup();
  parent.querySelectorAll('.ps-security-art,.ps-threat-grid').forEach(node => node.remove());
  const root = document.createElement('section');
  root.className = 'ps-security-art';
  root.setAttribute('aria-label', 'Rotating domain radar illustration, not scan results.');
  root.innerHTML = `<div class="ps-art-header"><span class="ps-art-dot"></span>DOMAIN SCANNER<span>ILLUSTRATIVE SCAN</span></div>
    <div class="ps-native-radar">
      <svg viewBox="0 0 320 320" role="img" aria-label="Continuously rotating radar scan">
        <circle cx="160" cy="160" r="128" fill="#102337" fill-opacity=".6" stroke="#446786" stroke-width="3"/>
        <g fill="none" stroke="#365772" stroke-width="1.5">
          <circle cx="160" cy="160" r="96"/><circle cx="160" cy="160" r="64"/><circle cx="160" cy="160" r="32"/>
          <path d="M32 160h256M160 32v256" stroke-opacity=".45"/>
        </g>
        <g class="ps-native-sweep">
          <path d="M160 160L160 34A126 126 0 0 1 269 97Z" fill="#6094bd" fill-opacity=".16"/>
          <path d="M160 160V34" stroke="#84afcf" stroke-width="2"/>
        </g>
        <circle cx="160" cy="160" r="5" fill="#8ab1ce"/>
        <g fill="#8ba4ba" font-size="8" text-anchor="middle" font-family="sans-serif">
          <text x="160" y="17">000&deg;</text><text x="304" y="163">090&deg;</text>
          <text x="160" y="308">180&deg;</text><text x="16" y="163">270&deg;</text>
        </g>
      </svg>
    </div>
    <div class="ps-scan-signals"><span><i></i>Certificates</span><span><i></i>Domain patterns</span><span><i></i>Page evidence</span></div>
    <div class="ps-scan-credit"><span>Domain radar</span><span>Illustration, not scan results</span></div>`;
  parent.appendChild(root);
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  const sweep = root.querySelector<SVGGElement>('.ps-native-sweep')!;
  let frame = 0;
  let disposed = false;
  const rotate = (time: number) => {
    if (disposed) return;
    sweep.setAttribute('transform', `rotate(${(time % 4000) * .09} 160 160)`);
    frame = requestAnimationFrame(rotate);
  };
  const update = () => {
    cancelAnimationFrame(frame);
    if (!motion.matches) frame = requestAnimationFrame(rotate);
  };
  update();
  motion.addEventListener('change', update);
  const cleanup = () => {
    disposed = true;
    cancelAnimationFrame(frame);
    motion.removeEventListener('change', update);
    root.remove();
    if (instances.get(parent)?.root === root) instances.delete(parent);
  };
  instances.set(parent, {root, cleanup});
  return cleanup;
}
