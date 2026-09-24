(() => {
  const root = document.documentElement;
  const body = document.body;

  const savedTheme = localStorage.getItem('tlm-theme');
  if (savedTheme === 'dark' || savedTheme === 'light') root.dataset.theme = savedTheme;

  document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
      root.dataset.theme = next;
      localStorage.setItem('tlm-theme', next);
    });
  });

  const closeSidebar = () => body.classList.remove('sidebar-open');
  document.querySelectorAll('[data-sidebar-open]').forEach((btn) => btn.addEventListener('click', () => body.classList.add('sidebar-open')));
  document.querySelectorAll('[data-sidebar-close]').forEach((btn) => btn.addEventListener('click', closeSidebar));
  document.querySelectorAll('.sidebar a').forEach((a) => a.addEventListener('click', closeSidebar));
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeSidebar(); });

  document.querySelectorAll('[data-toast-close]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const toast = btn.closest('.toast');
      if (!toast) return;
      toast.classList.add('hiding');
      setTimeout(() => toast.remove(), 210);
    });
  });
  document.querySelectorAll('.toast.success').forEach((toast) => {
    setTimeout(() => {
      if (!toast.isConnected) return;
      toast.classList.add('hiding');
      setTimeout(() => toast.remove(), 210);
    }, 6000);
  });

  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const selector = btn.getAttribute('data-copy');
      const target = selector ? document.querySelector(selector) : null;
      const value = target ? (target.value || target.textContent || '').trim() : (btn.dataset.copyValue || '');
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        const old = btn.innerHTML;
        btn.textContent = 'کپی شد';
        setTimeout(() => { btn.innerHTML = old; }, 1400);
      } catch (_) {
        if (target && typeof target.select === 'function') { target.select(); document.execCommand('copy'); }
      }
    });
  });

  const cards = [...document.querySelectorAll('[data-location-card]')];
  const search = document.querySelector('[data-location-search]');
  const statusFilter = document.querySelector('[data-status-filter]');
  const countryFilter = document.querySelector('[data-country-filter]');
  const applyLocationFilters = () => {
    const q = (search?.value || '').trim().toLowerCase();
    const status = statusFilter?.value || 'all';
    const country = countryFilter?.value || 'all';
    let visible = 0;
    cards.forEach((card) => {
      const haystack = (card.dataset.search || '').toLowerCase();
      const statusOk = status === 'all' || card.dataset.status === status;
      const countryOk = country === 'all' || card.dataset.country === country;
      const show = (!q || haystack.includes(q)) && statusOk && countryOk;
      card.classList.toggle('hidden', !show);
      if (show) visible += 1;
    });
    const counter = document.querySelector('[data-visible-count]');
    if (counter) counter.textContent = String(visible);
    const empty = document.querySelector('[data-filter-empty]');
    if (empty) empty.classList.toggle('hidden', visible !== 0 || cards.length === 0);
  };
  [search, statusFilter, countryFilter].filter(Boolean).forEach((el) => el.addEventListener(el.tagName === 'INPUT' ? 'input' : 'change', applyLocationFilters));

  const transportInputs = [...document.querySelectorAll('input[name="tor_transport_mode"]')];
  const bridgeFields = document.querySelector('[data-bridge-fields]');
  const updateTransportVisibility = () => {
    if (!bridgeFields) return;
    const selected = document.querySelector('input[name="tor_transport_mode"]:checked');
    bridgeFields.dataset.hidden = selected?.value === 'obfs4' ? 'false' : 'true';
  };
  transportInputs.forEach((el) => el.addEventListener('change', updateTransportVisibility));
  updateTransportVisibility();

  const wizard = document.querySelector('[data-wizard]');
  if (wizard) {
    const countrySelect = wizard.querySelector('[data-country-select]');
    const countryName = wizard.querySelector('[data-country-name]');
    const syncCountryName = () => {
      if (!countrySelect || !countryName) return;
      const option = countrySelect.selectedOptions?.[0];
      const selectedName = option?.dataset.countryNameValue || '';
      if (!selectedName) return;
      const auto = countryName.dataset.autoCountryName === '1';
      if (!countryName.value.trim() || auto) {
        countryName.value = selectedName;
        countryName.dataset.autoCountryName = '1';
      }
    };
    if (countryName) {
      countryName.addEventListener('input', () => {
        countryName.dataset.autoCountryName = countryName.value.trim() ? '0' : '1';
      });
    }
    if (countrySelect) countrySelect.addEventListener('change', syncCountryName);
    syncCountryName();
    const panels = [...wizard.querySelectorAll('[data-wizard-panel]')];
    const steps = [...document.querySelectorAll('[data-wizard-step]')];
    let current = 0;

    const showStep = (index) => {
      current = Math.max(0, Math.min(index, panels.length - 1));
      panels.forEach((panel, i) => panel.classList.toggle('active', i === current));
      steps.forEach((step, i) => {
        step.classList.toggle('active', i === current);
        step.classList.toggle('done', i < current);
      });
      if (current === panels.length - 1) updateReview();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    const validateCurrent = () => {
      const required = [...panels[current].querySelectorAll('[required]')];
      for (const field of required) {
        if (!field.checkValidity()) { field.reportValidity(); return false; }
      }
      const inboundPort = wizard.querySelector('[name="xui_inbound_port"]');
      const gatewayPort = wizard.querySelector('[name="gateway_port"]');
      if (inboundPort?.value && gatewayPort?.value && inboundPort.value === gatewayPort.value) {
        gatewayPort.setCustomValidity('پورت Gateway و Inbound باید متفاوت باشند.');
        gatewayPort.reportValidity();
        gatewayPort.setCustomValidity('');
        return false;
      }
      return true;
    };

    const updateReview = () => {
      const get = (name) => wizard.querySelector(`[name="${name}"]`);
      const text = (name, fallback = 'خودکار') => get(name)?.value?.trim() || fallback;
      const countryField = get('country_code');
      const countryLabel = countryField?.selectedOptions?.[0]?.textContent?.trim() || '—';
      const rows = {
        '[data-review-name]': text('name', '—'),
        '[data-review-country]': countryLabel,
        '[data-review-inbound]': text('xui_inbound_port'),
        '[data-review-gateway]': text('gateway_port', '—'),
        '[data-review-state]': get('enabled')?.checked ? 'فعال' : 'غیرفعال',
      };
      Object.entries(rows).forEach(([selector, value]) => {
        const el = wizard.querySelector(selector);
        if (el) el.textContent = value;
      });
      const xuiCount = wizard.querySelectorAll('input[name="inbound_tags"]:checked').length;
      const pgCount = wizard.querySelectorAll('input[name="pasarguard_inbound_tags"]:checked').length;
      const extra = wizard.querySelector('[data-review-extra]');
      if (extra) {
        const values = [];
        if (xuiCount) values.push(`3x-ui: ${xuiCount}`);
        if (pgCount) values.push(`PasarGuard: ${pgCount}`);
        extra.textContent = values.length ? values.join(' · ') : 'بدون Route اضافی';
      }
    };

    wizard.querySelectorAll('[data-wizard-next]').forEach((btn) => btn.addEventListener('click', () => { if (validateCurrent()) showStep(current + 1); }));
    wizard.querySelectorAll('[data-wizard-prev]').forEach((btn) => btn.addEventListener('click', () => showStep(current - 1)));
    steps.forEach((step, i) => step.addEventListener('click', () => { if (i <= current || validateCurrent()) showStep(i); }));
    showStep(0);
  }

  const logAutoRefresh = document.querySelector('[data-log-auto-refresh]');
  if (logAutoRefresh) {
    let timer = null;
    const toggle = () => {
      if (logAutoRefresh.checked) timer = setInterval(() => window.location.reload(), 10000);
      else if (timer) { clearInterval(timer); timer = null; }
    };
    logAutoRefresh.addEventListener('change', toggle);
    toggle();
  }
})();
