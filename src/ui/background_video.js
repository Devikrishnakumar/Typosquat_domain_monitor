// Keep one full-viewport background across Streamlit reruns.
(() => {
  const source = 'https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260328_065045_c44942da-53c6-4804-b734-f9e07fc22e08.mp4';
  const existing = document.getElementById('ps-video-background');
  if (existing?.dataset.source === source) return;
  if (window.__phishshieldHls) {
    window.__phishshieldHls.destroy();
    delete window.__phishshieldHls;
  }
  existing?.remove();
  const backdrop = document.createElement('div');
  backdrop.id = 'ps-video-background';
  backdrop.dataset.source = source;
  backdrop.setAttribute('aria-hidden', 'true');
  const video = document.createElement('video');
  video.autoplay = true;
  video.loop = true;
  video.muted = true;
  video.playsInline = true;
  video.preload = 'metadata';
  backdrop.append(video, document.createElement('div'));
  document.body.prepend(backdrop);

  const start = () => {
    video.src = source;
    const play = () => video.play().catch(() => {
      document.addEventListener('pointerdown', () => video.play().catch(() => {}), {once: true});
    });
    video.addEventListener('canplay', play, {once: true});
    video.load();
    play();
  };
  if ('requestIdleCallback' in window) window.requestIdleCallback(start, {timeout: 1500});
  else window.setTimeout(start, 300);
})();
