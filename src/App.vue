<script setup lang="ts">
import HelloWorld from './components/HelloWorld.vue'

import initVetkd, {
  TransportSecretKey,
  IBECiphertext,
  InitOutput as VetkdUtilsOutput,
} from 'vetkd-utils';

let initVetkdPromise: Promise<VetkdUtilsOutput> | null = null;
const getVetkd = async () => {
  if (!initVetkdPromise) {
    initVetkdPromise = initVetkd();
  }

  return await initVetkdPromise;
};

const hex_decode = (hexString: any) => {
  if (!hexString) return;
  return Uint8Array.from(
      hexString.match(/.{1,2}/g).map((byte: any) => parseInt(byte, 16))
  );
};
const hex_encode = (bytes: any) =>
    bytes.reduce(
        (str: string, byte: any) => str + byte.toString(16).padStart(2, "0"),
        ""
    );

async function ibe_encrypt({
  actor,
  message,
  principal,
}: {
  actor: any;
  message: string;
  principal: any;
}): Promise<any> {
  await getVetkd();

  const pk_bytes_hex = await actor.ibe_encryption_key();

  const message_encoded = new TextEncoder().encode(message);
  const seed = window.crypto.getRandomValues(new Uint8Array(32));

  const ibe_ciphertext = IBECiphertext.encrypt(
      hex_decode(pk_bytes_hex),
      principal.toUint8Array(),
      message_encoded,
      seed
  );
  return hex_encode(ibe_ciphertext.serialize());
}

async function ibe_decrypt({
  actor,
  ibe_ciphertext_hex,
  principal,
}: {
  actor: any;
  ibe_ciphertext_hex: string;
  principal: any;
}) {
  await getVetkd();

  const tsk_seed = window.crypto.getRandomValues(new Uint8Array(32));
  const tsk = new TransportSecretKey(tsk_seed);
  const ek_bytes_hex = await actor.encrypted_ibe_decryption_key_for_caller(tsk.public_key());
  const pk_bytes_hex = await actor.ibe_encryption_key();

  const k_bytes = tsk.decrypt(
      hex_decode(ek_bytes_hex),
      hex_decode(pk_bytes_hex),
      principal.toUint8Array()
  );

  const ibe_ciphertext = IBECiphertext.deserialize(
      hex_decode(ibe_ciphertext_hex)
  );
  const ibe_plaintext = ibe_ciphertext.decrypt(k_bytes);
  return new TextDecoder().decode(ibe_plaintext);
}

</script>

<template>
  <div>
    <a href="https://vitejs.dev" target="_blank">
      <img src="/vite.svg" class="logo" alt="Vite logo" />
    </a>
    <a href="https://vuejs.org/" target="_blank">
      <img src="./assets/vue.svg" class="logo vue" alt="Vue logo" />
    </a>
  </div>
  <HelloWorld msg="Vite + Vue" />
</template>

<style scoped>
.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: filter 300ms;
}
.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}
.logo.vue:hover {
  filter: drop-shadow(0 0 2em #42b883aa);
}
</style>
