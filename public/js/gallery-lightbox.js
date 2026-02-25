(function(){
  const items = Array.from(document.querySelectorAll('[data-gallery-item]'));
  const lb = document.querySelector('#lightbox');
  if (!lb || items.length === 0) return;

  const mediaWrap = lb.querySelector('.lightbox-media');
  const capEl = lb.querySelector('[data-lb-caption]');
  const btnPrev = lb.querySelector('[data-lb-prev]');
  const btnNext = lb.querySelector('[data-lb-next]');
  const btnClose = lb.querySelector('[data-lb-close]');

  let index = 0;

  function render(i){
    index = (i + items.length) % items.length;
    const el = items[index];
    const type = el.getAttribute('data-type');
    const src = el.getAttribute('data-src');
    const caption = el.getAttribute('data-caption') || '';

    mediaWrap.innerHTML = '';
    if (type === 'video'){
      const v = document.createElement('video');
      v.src = src;
      v.controls = true;
      v.playsInline = true;
      v.preload = 'metadata';
      mediaWrap.appendChild(v);
    } else {
      const img = document.createElement('img');
      img.src = src;
      img.alt = caption || 'Gallery item';
      mediaWrap.appendChild(img);
    }
    capEl.textContent = caption;
  }

  function open(i){
    render(i);
    lb.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function close(){
    lb.classList.remove('open');
    mediaWrap.innerHTML = '';
    document.body.style.overflow = '';
  }

  items.forEach((el, i) => {
    el.addEventListener('click', () => open(i));
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        open(i);
      }
    });
  });

  btnPrev.addEventListener('click', () => render(index - 1));
  btnNext.addEventListener('click', () => render(index + 1));
  btnClose.addEventListener('click', close);

  lb.addEventListener('click', (e) => {
    if (e.target === lb) close();
  });

  window.addEventListener('keydown', (e) => {
    if (!lb.classList.contains('open')) return;
    if (e.key === 'Escape') close();
    if (e.key === 'ArrowLeft') render(index - 1);
    if (e.key === 'ArrowRight') render(index + 1);
  });
})();
