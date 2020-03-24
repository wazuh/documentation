  /* Delete old cached redirects from /current */
  const current_url = window.location.href;
  const parts = current_url.split('/');
  const fetch_url = parts[0] + '//' + parts[2] + '/current/' + parts.slice(4).join('/');
  fetch(fetch_url, {cache: "no-cache"})
    .then(response => {
      /* Fixed redirects, do nothing */
    });
