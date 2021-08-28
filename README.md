
yescrypt-js
===========

A pure javascript implementation of [yescript] algorithm.

The code is based on [origin work](https://github.com/defuse/yescrypt),
and then optimized for performance and refined for readability and
modularization.

Performance
-----------

For parameters suggested by [yescript](https://github.com/openwall/yescrypt/blob/main/PARAMETERS), it shall
be acceptable for use in browser/client side.

- Small and fast (N=2048, r=8, p=1)
    ```
    Input 16B, Salt 16B:
      24.9 ops/s, ±1.27%    | slowest, 0.64% slower

    Input 256B, Salt 16B:
      25.06 ops/s, ±0.92%   | fastest

    Input 256B, Salt 256B:
      25 ops/s, ±1.19%      | 0.24% slower

    Input 4K, Salt 16B:
      25.05 ops/s, ±1.16%   | 0.04% slower

    Input 4K, Salt 256B:
      25.03 ops/s, ±1.23%   | 0.12% slower
    ```
- Large and slow (N=4096, r=16, p=1)

    ```
    Input 16B, Salt 16B:
      6.314 ops/s, ±1.42%   | 0.06% slower
      
    Input 256B, Salt 16B:
      6.317 ops/s, ±1.60%   | 0.02% slower
  
    Input 256B, Salt 256B:
      6.162 ops/s, ±2.53%   | slowest, 2.47% slower
  
    Input 4K, Salt 16B:
      6.318 ops/s, ±1.30%   | fastest
  
    Input 4K, Salt 256B:
      6.232 ops/s, ±1.49%   | 1.36% slower
  
    ```

[yescript]: https://www.openwall.com/yescrypt/
