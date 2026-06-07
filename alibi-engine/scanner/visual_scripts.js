/* ─────────────────────────────────────────────────────────────
   alibi visual companion · interactive layer
   Vanilla JS, no dependencies, no network requests.
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";

  var doc = document;
  var body = doc.body;

  /* ── (1) filter chips ─────────────────────────────────── */
  var chips    = doc.querySelectorAll('.chip[data-filter]');
  var findings = doc.querySelectorAll('#findings .finding');
  var groups   = doc.querySelectorAll('#findings .sev-group');
  var catFilterUi   = doc.getElementById('cat-filter');
  var catFilterName = doc.getElementById('cat-filter-name');
  var catFilter = null;

  function activeSet(name) {
    var s = {};
    doc.querySelectorAll('.chip[data-filter="' + name + '"][aria-pressed="true"]').forEach(function (c) {
      s[c.dataset.val] = true;
    });
    return s;
  }

  function applyFilters() {
    var sev  = activeSet('sev');
    var kind = activeSet('kind');
    findings.forEach(function (f) {
      var visible = sev[f.dataset.severity] && kind[f.dataset.kind];
      if (catFilter && f.dataset.category !== catFilter) { visible = false; }
      f.style.display = visible ? '' : 'none';
    });
    groups.forEach(function (g) {
      var ul = g.nextElementSibling;
      if (!ul) { return; }
      var any = false;
      ul.querySelectorAll('.finding').forEach(function (f) {
        if (f.style.display !== 'none') { any = true; }
      });
      g.style.display = any ? '' : 'none';
      ul.style.display = any ? '' : 'none';
    });
  }

  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      var on = chip.getAttribute('aria-pressed') === 'true';
      chip.setAttribute('aria-pressed', on ? 'false' : 'true');
      applyFilters();
    });
  });

  var clearBtn = doc.getElementById('clear-filters');
  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      chips.forEach(function (c) {
        if (c.dataset.filter === 'sev') {
          c.setAttribute('aria-pressed', c.dataset.val === 'INFO' ? 'false' : 'true');
        } else {
          c.setAttribute('aria-pressed', 'true');
        }
      });
      setCatFilter(null);
      applyFilters();
    });
  }

  function setCatFilter(cat) {
    catFilter = cat;
    if (!catFilterUi) { applyFilters(); return; }
    if (cat) {
      if (catFilterName) { catFilterName.textContent = cat; }
      catFilterUi.hidden = false;
    } else {
      catFilterUi.hidden = true;
    }
    applyFilters();
  }

  var catFilterClear = doc.getElementById('cat-filter-clear');
  if (catFilterClear) {
    catFilterClear.addEventListener('click', function () { setCatFilter(null); });
  }

  /* category map tiles → filter */
  doc.querySelectorAll('.cat-tile').forEach(function (tile) {
    tile.addEventListener('click', function () {
      var cat = tile.dataset.cat;
      setCatFilter(catFilter === cat ? null : cat);
      // scroll to findings section
      var sec = doc.getElementById('findings');
      if (sec) { window.scrollTo({ top: sec.offsetTop - 16, behavior: 'smooth' }); }
    });
  });

  /* category tags inside finding cards → filter same category */
  doc.querySelectorAll('.cat-tag[data-cat]').forEach(function (t) {
    t.addEventListener('click', function (ev) {
      ev.stopPropagation();
      setCatFilter(t.dataset.cat);
    });
  });

  applyFilters();

  /* ── (2) copy buttons ─────────────────────────────────── */
  doc.querySelectorAll('.copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      var text = btn.dataset.copy || '';
      var done = function () {
        var label = btn.textContent;
        btn.textContent = 'copied';
        btn.classList.add('copied');
        setTimeout(function () { btn.textContent = label; btn.classList.remove('copied'); }, 1200);
      };
      function fallback() {
        var ta = doc.createElement('textarea');
        ta.value = text; ta.setAttribute('readonly', '');
        ta.style.position = 'absolute'; ta.style.left = '-9999px';
        body.appendChild(ta); ta.select();
        try { doc.execCommand('copy'); } catch (e) {}
        body.removeChild(ta);
        done();
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, fallback);
      } else { fallback(); }
    });
  });

  /* ── (3) expand metadata ──────────────────────────────── */
  doc.querySelectorAll('.meta-expand').forEach(function (btn) {
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      var card = btn.closest('.finding');
      var isExp = card.classList.toggle('is-expanded');
      var hiddenCount = card.querySelectorAll('.kv.hidden').length;
      btn.lastChild && (btn.lastChild.nodeType === 3) && (btn.lastChild.textContent = isExp ? 'collapse' : ('expand · ' + hiddenCount + ' more'));
      // simpler: rebuild label
      btn.innerHTML = '<span class="car"></span>' + (isExp ? 'collapse' : ('expand · ' + hiddenCount + ' more'));
    });
  });

  /* ── (4) hover/click cross-linking ────────────────────── */
  // Build a map of pattern → [related elements] (findings, rows, dots)
  function tokens(el) {
    var out = [];
    if (el.dataset.pattern)  { out.push(el.dataset.pattern.toLowerCase()); }
    if (el.dataset.keys)     { el.dataset.keys.toLowerCase().split(/\s+/).forEach(function (k) { if (k) { out.push(k); } }); }
    return out;
  }

  var allLinkable = []
    .concat([].slice.call(doc.querySelectorAll('.finding')))
    .concat([].slice.call(doc.querySelectorAll('tr.has-link')));

  function highlightRelated(el) {
    var t = tokens(el);
    if (!t.length) { return; }
    body.classList.add('has-focus');
    allLinkable.forEach(function (other) {
      if (other === el) { return; }
      var ot = tokens(other);
      var hit = ot.some(function (k) { return t.indexOf(k) !== -1; });
      if (hit) { other.classList.add('is-related'); }
    });
    el.classList.add('is-related');
    // timeline dots
    doc.querySelectorAll('.tl-svg circle.dot').forEach(function (c) {
      var tid = c.dataset.target;
      if (tid && el.id === tid) { c.classList.add('is-active'); }
    });
  }
  function clearRelated() {
    body.classList.remove('has-focus');
    allLinkable.forEach(function (el) { el.classList.remove('is-related'); });
    doc.querySelectorAll('.tl-svg circle.dot.is-active').forEach(function (c) { c.classList.remove('is-active'); });
  }

  allLinkable.forEach(function (el) {
    el.addEventListener('mouseenter', function () { highlightRelated(el); });
    el.addEventListener('mouseleave', function () { clearRelated(); });
  });

  /* ── (5) timeline dots ────────────────────────────────── */
  var tlWrap = doc.getElementById('timeline');
  var tlTooltip = doc.getElementById('tl-tooltip');
  var tlSvg = tlWrap.querySelector('.tl-svg');
  var tlHoverLine = doc.getElementById('tl-hover-line');
  var tlHoverText = doc.getElementById('tl-hover-text');

  // Map SVG-x → days-ago and readable date.  x=44 → -180d ; x=1196 → today.
  var TODAY_MS = Date.UTC(2026, 4, 25);   // 2026-05-25
  var DAY = 86400000;
  function svgXToDate(svgX) {
    // Log-scale inverse · live (220..1196) covers 0..180d ; archive (44..196) is log-compressed >180d.
    var daysAgo, archived = false;
    if (svgX >= 220) {
      var frac = (1196 - svgX) / 976;        // 0 at today, 1 at -180d
      daysAgo = Math.exp(frac * Math.log(181)) - 1;
    } else if (svgX >= 200) {
      // fold zone — snap to 180d
      daysAgo = 180;
    } else {
      archived = true;
      var fracA = (196 - svgX) / 152;        // 0 at -180d edge, 1 at ~3000d edge
      daysAgo = 180 * Math.pow(3000 / 180, fracA);
    }
    daysAgo = Math.max(0, Math.round(daysAgo));
    var d = new Date(TODAY_MS - daysAgo * DAY);
    var iso = d.getUTCFullYear() + '-' +
      String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
      String(d.getUTCDate()).padStart(2, '0');
    return { daysAgo: daysAgo, iso: iso, archived: archived };
  }
  function clientXToSvgX(clientX) {
    var r = tlSvg.getBoundingClientRect();
    return ((clientX - r.left) / r.width) * 1200;
  }

  tlSvg.addEventListener('mousemove', function (ev) {
    var sx = clientXToSvgX(ev.clientX);
    if (sx < 44 || sx > 1196) {
      tlHoverLine.classList.remove('is-active');
      tlHoverText.classList.remove('is-active');
      return;
    }
    tlHoverLine.setAttribute('x1', sx);
    tlHoverLine.setAttribute('x2', sx);
    tlHoverLine.classList.add('is-active');
    var info = svgXToDate(sx);
    tlHoverText.setAttribute('x', sx);
    tlHoverText.textContent = info.archived
      ? ('archived · ' + info.iso + '  ·  −' + info.daysAgo + 'd')
      : (info.iso + '  ·  −' + info.daysAgo + 'd');
    tlHoverText.classList.add('is-active');
  });
  tlSvg.addEventListener('mouseleave', function () {
    tlHoverLine.classList.remove('is-active');
    tlHoverText.classList.remove('is-active');
  });

  doc.querySelectorAll('.tl-svg circle.dot').forEach(function (c) {
    c.addEventListener('mouseenter', function (ev) {
      tlTooltip.innerHTML =
        '<span class="ttl-sev ' + c.dataset.sev + '">' + c.dataset.sev + '</span>' +
        '<span class="ttl-cat">' + c.dataset.cat + '</span>' +
        c.dataset.detail +
        '<span class="ttl-when">' + c.dataset.when + '</span>';
      tlTooltip.dataset.visible = 'true';
      // highlight related finding too
      var tid = c.dataset.target;
      if (tid) {
        var card = doc.getElementById(tid);
        if (card) { highlightRelated(card); }
      }
    });
    c.addEventListener('mousemove', function (ev) {
      var r = tlWrap.getBoundingClientRect();
      tlTooltip.style.left = (ev.clientX - r.left) + 'px';
      tlTooltip.style.top  = (ev.clientY - r.top) + 'px';
    });
    c.addEventListener('mouseleave', function () {
      tlTooltip.dataset.visible = 'false';
      clearRelated();
    });
    c.addEventListener('click', function () {
      var tid = c.dataset.target;
      if (!tid) { return; }
      var target = doc.getElementById(tid);
      if (!target) { return; }
      jumpToTarget(target);
    });
  });

  /* ── (6) named-items jump ─────────────────────────────── */
  doc.querySelectorAll('#named-list li[data-target]').forEach(function (li) {
    li.addEventListener('click', function () {
      var target = doc.getElementById(li.dataset.target);
      if (target) { jumpToTarget(target); }
    });
  });

  function jumpToTarget(target) {
    var top = target.getBoundingClientRect().top + window.pageYOffset - 28;
    window.scrollTo({ top: top, behavior: 'smooth' });
    // flash
    doc.querySelectorAll('.is-pinned').forEach(function (e) { e.classList.remove('is-pinned'); });
    target.classList.add('is-pinned');
    target.classList.add('is-expanded');
    setTimeout(function () { target.classList.remove('is-pinned'); }, 2200);
  }

  /* ── (7) CLEAN row toggle ─────────────────────────────── */
  doc.querySelectorAll('.toggle-clean').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var tbl = doc.getElementById(btn.dataset.target);
      if (!tbl) { return; }
      var hidden = tbl.querySelectorAll('tr.hidden').length > 0;
      tbl.querySelectorAll('tr.clean-row').forEach(function (r) {
        if (hidden) { r.classList.remove('hidden'); }
        else if (r.querySelector('.score[data-s="CLEAN"]')) { r.classList.add('hidden'); }
      });
      btn.textContent = hidden ? 'hide CLEAN' : 'show CLEAN';
      var shown = tbl.querySelectorAll('tbody tr:not(.hidden)').length;
      var total = tbl.querySelectorAll('tbody tr').length;
      var cleanHidden = tbl.querySelectorAll('tr.clean-row.hidden').length;
      var summary = btn.closest('.runtime-foot').querySelector('span');
      if (summary) {
        summary.innerHTML = '<b>' + shown + '</b> of ' + total + ' shown' +
          (cleanHidden ? ' · ' + cleanHidden + ' CLEAN hidden' : '');
      }
    });
  });

  /* ── (8) indicator donut · legend ↔ slice cross-highlight ─ */
  (function () {
    var legend = doc.getElementById('indi-legend');
    if (!legend) { return; }
    var slices = doc.querySelectorAll('.indi-donut .slice');
    var rows = legend.querySelectorAll('.row[data-tier]');
    function activate(tier) {
      slices.forEach(function (s) { s.classList.toggle('is-active', s.dataset.tier === tier); });
      rows.forEach(function (r) { r.classList.toggle('is-active', r.dataset.tier === tier); });
    }
    function deactivate() {
      slices.forEach(function (s) { s.classList.remove('is-active'); });
      rows.forEach(function (r) { r.classList.remove('is-active'); });
    }
    rows.forEach(function (r) {
      r.addEventListener('mouseenter', function () { activate(r.dataset.tier); });
      r.addEventListener('mouseleave', deactivate);
    });
    slices.forEach(function (s) {
      s.addEventListener('mouseenter', function () { activate(s.dataset.tier); });
      s.addEventListener('mouseleave', deactivate);
    });
  })();

  /* ── (9) keyboard escape clears state ─────────────────── */
  doc.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      clearRelated();
      doc.querySelectorAll('.is-pinned').forEach(function (el) { el.classList.remove('is-pinned'); });
      tlTooltip.dataset.visible = 'false';
      if (catFilter) { setCatFilter(null); }
    }
  });

})();