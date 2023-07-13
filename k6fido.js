import k6fido from 'k6/x/k6fido';

export default function () {

  const keyPair = k6fido.generateKeyPair();
  console.log(`keypaid: ${keyPair}`);
}