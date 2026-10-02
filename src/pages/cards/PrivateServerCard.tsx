import {createSignal, JSX} from 'solid-js';

import Button from '@components/buttonTsx';
import MediaHeader from '@components/mediaHeader';
import {getPrivateServerConfig, setPrivateServerConfig, clearPrivateServerConfig} from '@lib/privateServer';

import AuthCard from '@/pages/AuthCard';
import {CardSpec, useAuthFlow} from '@/pages/authFlow';

type Spec = Extract<CardSpec, {name: 'privateServer'}>;

function removePrivateServerQuery() {
  const url = new URL(location.href);
  for(const key of ['private_ip', 'private_port', 'private_public_key', 'private_secure', 'private_server']) {
    url.searchParams.delete(key);
  }
  history.replaceState(null, '', url.href);
}

export default function PrivateServerCard(_props: {spec: Spec}) {
  const {navigate} = useAuthFlow();
  const saved = getPrivateServerConfig();
  const [address, setAddress] = createSignal(saved?.address || '');
  const [port, setPort] = createSignal(String(saved?.port || 28081));
  const [publicKey, setPublicKey] = createSignal(saved?.publicKey || '');
  const [secure, setSecure] = createSignal(saved?.secure || false);
  const [error, setError] = createSignal('');

  function save(event: Event) {
    event.preventDefault();
    try {
      setPrivateServerConfig({
        address: address(),
        port: Number(port()),
        publicKey: publicKey(),
        secure: secure()
      });
      removePrivateServerQuery();
      location.reload();
    } catch(err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  function clear() {
    clearPrivateServerConfig();
    removePrivateServerQuery();
    history.replaceState(null, '', location.pathname);
    location.reload();
  }

  const fields: JSX.Element = (
    <>
      <label>
        <span>Server IP or hostname</span>
        <input
          type="text"
          autocomplete="off"
          spellcheck={false}
          value={address()}
          onInput={(event) => setAddress(event.currentTarget.value)}
          placeholder="192.168.37.27"
        />
      </label>
      <label>
        <span>MTProto HTTP port</span>
        <input
          type="number"
          min="1"
          max="65535"
          value={port()}
          onInput={(event) => setPort(event.currentTarget.value)}
        />
      </label>
      <label>
        <span>Server RSA public key (PEM)</span>
        <textarea
          rows="12"
          spellcheck={false}
          value={publicKey()}
          onInput={(event) => setPublicKey(event.currentTarget.value)}
          placeholder="-----BEGIN PUBLIC KEY-----"
        />
      </label>
      <label class="private-server-secure">
        <input
          type="checkbox"
          checked={secure()}
          onChange={(event) => setSecure(event.currentTarget.checked)}
        />
        <span>Use HTTPS</span>
      </label>
      <ShowError value={error()}/>
      <Button class="btn-primary btn-color-primary" onClick={save}>Save and restart</Button>
      <Button class="btn-primary btn-secondary btn-primary-transparent primary" onClick={() => navigate({name: 'signIn'})}>
        Back
      </Button>
      {saved && (
        <Button class="btn-primary btn-secondary btn-primary-transparent primary" onClick={clear}>
          Use official Telegram servers
        </Button>
      )}
    </>
  );

  return (
    <AuthCard
      header={
        <MediaHeader>
          <MediaHeader.Title tag="h1">Private Telegram server</MediaHeader.Title>
          <MediaHeader.Subtitle class="secondary">
            Set the standalone server address, HTTP port, and RSA public key used by the MTProto handshake.
          </MediaHeader.Subtitle>
        </MediaHeader>
      }
    >
      <div class="private-server-fields">{fields}</div>
    </AuthCard>
  );
}

function ShowError(props: {value: string}) {
  return props.value ? <div class="private-server-error">{props.value}</div> : null;
}
