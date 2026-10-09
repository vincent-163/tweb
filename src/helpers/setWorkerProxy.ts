import {CURRENT_ACCOUNT_QUERY_PARAM} from '@lib/accounts/constants';
import {THREADED_WORKER_PROTOCOL_QUERY_PARAM} from '@lib/threadedWorkerTypes';
import {getPrivateServerConfig} from '@lib/privateServer';

export function makeWorkerURL(url: string | URL) {
  if(!(url instanceof URL)) {
    url = new URL(url + '', location.href);
  }

  if(url.protocol !== 'blob:') {
    const params = new URLSearchParams(location.search);
    params.forEach((value, key) => {
      if(key === CURRENT_ACCOUNT_QUERY_PARAM || key === THREADED_WORKER_PROTOCOL_QUERY_PARAM) return;
      (url as URL).searchParams.set(key, value);
    });

    const privateServer = getPrivateServerConfig();
    if(privateServer) {
      const privateParams = new URLSearchParams({
        private_ip: privateServer.address,
        private_port: privateServer.port + '',
        private_public_key: privateServer.publicKey,
        private_secure: privateServer.secure ? '1' : '0'
      });
      privateParams.forEach((value, key) => (url as URL).searchParams.set(key, value));
    }
  }

  // exclude useless params
  (url as URL).searchParams.delete('swfix');

  return url;
}

export default function setWorkerProxy() {
  // * hook worker constructor to set search parameters (test, debug, etc)
  const workerHandler = {
    construct(target: any, args: any) {
      args[0] = makeWorkerURL(args[0]);
      return new target(...args);
    }
  };

  [
    typeof(Worker) !== 'undefined' && Worker,
    typeof(SharedWorker) !== 'undefined' && SharedWorker
  ].filter(Boolean).forEach((w) => {
    window[w.name as any] = new Proxy(w, workerHandler);
  });
}

setWorkerProxy();
