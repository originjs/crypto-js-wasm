import { init as browserInit, RsaPrivate as browserRsaPrivate, RsaPublic as browserRsaPublic } from './rsa_bg_browser';
import { init as nodejsInit, RsaPrivate as nodejsRsaPrivate, RsaPublic as nodejsRsaPublic } from './rsa_bg_nodejs';

let init, RsaPrivate, RsaPublic;
if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
  console.log('Browser detected');

  init = browserInit;
  RsaPrivate = browserRsaPrivate;
  RsaPublic = browserRsaPublic;
} else if (typeof process !== 'undefined' && process.versions != null && process.versions.node != null) {
  console.log('Nodejs detected');

  init = nodejsInit;
  RsaPrivate = nodejsRsaPrivate;
  RsaPublic = nodejsRsaPublic;
} else {
  throw Error('Only browser and nodejs supported');
}

export {init, RsaPrivate, RsaPublic};
