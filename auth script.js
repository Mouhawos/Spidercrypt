// auth-script.js
document.addEventListener('DOMContentLoaded', function () {
    const signInButton = document.createElement('button');
    signInButton.innerText = 'Se connecter';
    signInButton.addEventListener('click', () => {
        // Ouvrir le widget de connexion de Clerk
        Clerk.openSignIn({
            container: '#app',
        });
    });

    const signOutButton = document.createElement('button');
    signOutButton.innerText = 'Se déconnecter';
    signOutButton.addEventListener('click', () => {
        // Déconnecter l'utilisateur
        Clerk.signOut();
    });

    // Vérifier si l'utilisateur est connecté
    if (Clerk.user) {
        document.getElementById('app').appendChild(signOutButton);
    } else {
        document.getElementById('app').appendChild(signInButton);
    }
});
