importScripts('https://www.gstatic.com/firebasejs/10.8.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.8.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyAX6ooPWJb2LWbWop-YxAcCjpgtoMzkIDA",
  authDomain: "trouvemoi-c1b01.firebaseapp.com",
  projectId: "trouvemoi-c1b01",
  storageBucket: "trouvemoi-c1b01.firebasestorage.app",
  messagingSenderId: "317041094178",
  appId: "1:317041094178:web:8c5fce11bc259b4d3d647b"
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  console.log('[firebase-messaging-sw.js] Message reçu en arrière-plan : ', payload);
  const notificationTitle = payload.notification.title;
  const notificationOptions = {
    body: payload.notification.body,
    icon: 'https://res.cloudinary.com/gxm35ndf/image/upload/v1794045762/TROUVEMOI_PNG.jpg'
  };
  self.registration.showNotification(notificationTitle, notificationOptions);
});
