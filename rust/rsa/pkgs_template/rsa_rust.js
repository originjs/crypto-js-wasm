let init, RsaPrivate, RsaPublic;
if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
  console.log('Browser detected');

  await import('./browser/rsa_rust.js').then(RsaBrowser => {
    init = RsaBrowser.init;
    RsaPrivate = RsaBrowser.RsaPrivate;
    RsaPublic = RsaBrowser.RsaPublic;
  });

  await init();
  console.log(new RsaPrivate(1024).getPrivateKeyContent('pem'));
} else if (typeof process !== 'undefined' && process.versions != null && process.versions.node != null) {
  console.log('Nodejs detected');

  await import('./nodejs/rsa_rust.js').then(RsaNode => {
    init = RsaNode.init;
    RsaPrivate = RsaNode.RsaPrivate;
    RsaPublic = RsaNode.RsaPublic;
  });
} else {
  throw Error('Only browser and nodejs supported');
}

export {init, RsaPrivate, RsaPublic};
