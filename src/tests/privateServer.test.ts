import {describe, expect, it} from 'vitest';

import {
  parsePrivateServerConfig,
  parsePublicPemHex,
  privateServerHttpUrl
} from '@lib/privateServer';

const officialPublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----`;

describe('private server configuration', () => {
  it('validates and normalizes an IPv4 server with a PEM RSA key', () => {
    const config = parsePrivateServerConfig({
      address: ' 192.168.37.27 ',
      port: '28081',
      publicKey: officialPublicKey
    });

    expect(config).toMatchObject({
      address: '192.168.37.27',
      port: 28081,
      secure: false
    });
    expect(parsePublicPemHex(config.publicKey)).toEqual(parsePublicPemHex(officialPublicKey));
    expect(privateServerHttpUrl(config)).toBe('http://192.168.37.27:28081/apiw1');
  });

  it('rejects malformed addresses, ports, and keys', () => {
    expect(() => parsePrivateServerConfig({
      address: '192.168.37.999',
      port: 28081,
      publicKey: officialPublicKey
    })).toThrow('Invalid IPv4');
    expect(() => parsePrivateServerConfig({
      address: '192.168.37.27',
      port: 70000,
      publicKey: officialPublicKey
    })).toThrow('port');
    expect(() => parsePrivateServerConfig({
      address: '192.168.37.27',
      port: 28081,
      publicKey: 'not-a-key'
    })).toThrow();
  });
});
