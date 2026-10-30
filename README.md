# QRobot

QRobot is a live production post quantum registration and chain of custody tool for autonomous robotic systems on the Quantova network. It proves the registration, conformity assessment, commissioning, transfer and retirement of a robot unit, and it lets any third party confirm that history without trusting the party that created it.

QRobot proves records without disclosing them. Unit identities and operator details stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no commercial detail is ever published.

## What it records

Each record is a signed envelope of one of five types.

1. register, a manufacturer states the class, make, model, serial, autonomy level and mass of a new robot unit.
2. conformity, an assessor certifies that a registered unit was assessed against a named safety standard.
3. commission, an operator states that a unit was put into service at a named site.
4. transfer, the holder of a unit moves it to another party.
5. retire, the holder removes a unit from service and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a unit forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qrobot
```

## Use

```js
const qrobot = require('@quantovainc/qrobot');

const maker = qrobot.generateKey();
const unit = qrobot.register({
  key: maker,
  robotClass: 'industrial',
  make: 'Quantova Robotics',
  model: 'QR 200',
  serial: 'QR 2026 0001',
  autonomyLevel: 'supervised',
  massGrams: 120000,
  makerLabel: 'Quantova Robotics',
});

const anchored = await qrobot.anchor(unit, { seed, index: 0, network: 'testnet' });
const result = await qrobot.verify(anchored[0], { type: 'register', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural or legal person. The signer is a chain address, and linking an address to a manufacturer, assessor or operator is a separate attestation.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
