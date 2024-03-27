# k6fido

A bunch of random functions for k6 performance testing that I found missing, but useful in our work.

# Compile for development
```sh
xk6 build v0.50.0 \
  --with github.com/b4dc0d3rs/k6-fido=.

./k6 run k6fido.js
```

# Use

Just import:
```js
import k6fido from 'k6/x/k6fido';
```
