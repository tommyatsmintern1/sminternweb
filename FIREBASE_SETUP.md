Firebase setup and deploy steps

1. Install Firebase CLI (if not already):

```bash
npm install -g firebase-tools
```

2. Login to your Firebase account:

```bash
firebase login
```

3. Initialize or link your project (only if needed):

```bash
# If not initialized in this folder
firebase init
# Select Firestore and Hosting (if you want hosting)
```

4. Ensure Email/Password sign-in is enabled in the Firebase console: Authentication → Sign-in method → Email/Password (enable).

5. Deploy Firestore rules and indexes:

```bash
firebase deploy --only firestore
```

6. (Optional) Deploy hosting (if you want to host this site via Firebase Hosting):

```bash
firebase deploy --only hosting
```

Notes
- The project already includes `firebase-config.js` with your web app settings. Keep those values updated from the Firebase console (Project settings → SDK setup).
- Security rules in `firestore.rules` restrict all reads/writes to `/users/{uid}` and `/users/{uid}/applications/{appId}` to the authenticated owner. Adjust rules if you add admin roles.
- After deploying rules, test with an authenticated user to confirm reads/writes work correctly.
