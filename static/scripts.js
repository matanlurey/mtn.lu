(() => {
  // If the system prefers dark mode.
  let darkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;

  // If the user has set a preference.
  if (localStorage.getItem('darkMode') === 'true') {
    darkMode = true;
  } else if (localStorage.getItem('darkMode') === 'false') {
    darkMode = false;
  }

  // Set the theme.
  document.body.setAttribute('data-theme', darkMode ? 'dark' : 'light');

  // Toggle the theme.
  document.querySelector('[data-theme-toggle]').addEventListener('click', () => {
    darkMode = !darkMode;
    document.body.setAttribute('data-theme', darkMode ? 'dark' : 'light');
    localStorage.setItem('darkMode', darkMode);
  });

  // Run highlight.js if installed.
  hljs?.highlightAll();
})();
