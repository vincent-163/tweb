import setWorkerProxy, {makeWorkerURL} from '@helpers/setWorkerProxy';
import {clearPrivateServerConfig, parsePublicPemHex, setPrivateServerConfig} from '@lib/privateServer';

const privateServerPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhMK3z9IlOc1nxSnkZL+C
NYiGMs2AOuT5KHE5gNYAtnjDW8kCsBLV/Y/Du0t4lAES7XX7e70uDbD8Q+3gUGOZ
3FK10BjrBZTgQLKpukD8ibBTXtJ+mnP/3B6/81FwNmmNVXfuDyad19Mv7+HuFadL
VdgRhjZnJmwRtGaLUfjBltMqLiHH8QpLoI2DUUm+0b9a7lUa2P2qWcO94HFQutjF
lCXqLxBjE/xDuMsO2uPzda3vXiomChQThszu0wCUv/0hht3KIih/ejh75zD3E4ps
1kRSVzLrzZEpzjMFPesZVTkDorReHNbq1ywaygcAq6evXu5PBKhDFB/PHVlDMZpj
+wIDAQAB
-----END PUBLIC KEY-----`;

describe('setWorkerProxy', () => {
  test('does not require the Worker API to exist', () => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'Worker');
    expect(Reflect.deleteProperty(globalThis, 'Worker')).toBe(true);

    try {
      expect(() => setWorkerProxy()).not.toThrow();
    } finally {
      if(descriptor) Object.defineProperty(globalThis, 'Worker', descriptor);
    }
  });

  test('forwards a saved private-server configuration after the page query is cleared', () => {
    const originalUrl = location.href;
    history.replaceState(null, '', location.pathname);

    try {
      setPrivateServerConfig({
        address: '192.168.37.27',
        port: 28081,
        publicKey: privateServerPublicKey,
        secure: false
      });

      const workerUrl = makeWorkerURL('/assets/index.worker.js');
      expect(workerUrl.searchParams.get('private_ip')).toBe('192.168.37.27');
      expect(workerUrl.searchParams.get('private_port')).toBe('28081');
      expect(parsePublicPemHex(workerUrl.searchParams.get('private_public_key') || '')).toEqual(
        parsePublicPemHex(privateServerPublicKey)
      );
      expect(workerUrl.searchParams.get('private_secure')).toBe('0');
    } finally {
      clearPrivateServerConfig();
      history.replaceState(null, '', originalUrl);
    }
  });
});
