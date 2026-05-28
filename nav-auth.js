// assets/js/nav-auth.js
// Import this on every page to wire up nav auth state.
// Usage: import { initNav } from './assets/js/nav-auth.js';
//        initNav(auth);

export function initNav(auth, { signOut, onAuthStateChanged }) {
  const navProfile  = document.getElementById('nav-profile');
  const navLogin    = document.getElementById('nav-login');
  const navRegister = document.getElementById('nav-register');
  const navLogout   = document.getElementById('nav-logout');

  onAuthStateChanged(auth, (user) => {
    if (user) {
      if (navProfile)  navProfile.style.display  = 'inline-flex';
      if (navLogout)   navLogout.style.display   = 'inline-flex';
      if (navLogin)    navLogin.style.display    = 'none';
      if (navRegister) navRegister.style.display = 'none';
    } else {
      if (navProfile)  navProfile.style.display  = 'none';
      if (navLogout)   navLogout.style.display   = 'none';
      if (navLogin)    navLogin.style.display    = 'inline-flex';
      if (navRegister) navRegister.style.display = 'inline-flex';
    }
  });

  if (navLogout) {
    navLogout.addEventListener('click', async (e) => {
      e.preventDefault();
      await signOut(auth);
      window.location.href = 'index.html';
    });
  }
}
