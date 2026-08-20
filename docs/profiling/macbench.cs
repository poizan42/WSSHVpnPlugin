// Answers "is CNG slower than OpenSSL" by running the same managed code on both:
// System.Security.Cryptography uses CNG on Windows and OpenSSL on Linux, so the backend is the only
// variable. Run it on Windows and under WSL on the same machine, interleaving rounds, and the
// machine must be idle - a concurrent build once inflated CNG's apparent disadvantage threefold.
// Reports MiB/s; openssl speed reports decimal kB/s, so divide that by 1.048576 to compare.
// See 2026-08-20-cng-vs-openssl.md for the numbers and the conclusion.
using System.Diagnostics;
using System.Security.Cryptography;

var size = args.Length > 0 ? int.Parse(args[0]) : 32768;
var data = new byte[size];
Random.Shared.NextBytes(data);
var key = new byte[32];
Random.Shared.NextBytes(key);
var dest = new byte[64];

using var mac = new HMACSHA256(key);
using var gcm = new AesGcm(key, 16);
var nonce = new byte[12];
var tag = new byte[16];
var ct = new byte[size];

Console.WriteLine($"{Run("sha256", () => SHA256.HashData(data, dest)):F0} "
    + $"{Run("hmac", () => mac.TryComputeHash(data, dest, out _)):F0} "
    + $"{Run("gcm", () => gcm.Encrypt(nonce, data, ct, tag)):F0}");

double Run(string name, Action op)
{
    for (var i = 0; i < 100; i++)
    {
        op();
    }

    var sw = Stopwatch.StartNew();
    long ops = 0;
    while (sw.Elapsed.TotalSeconds < 1.0)
    {
        for (var i = 0; i < 32; i++)
        {
            op();
        }

        ops += 32;
    }

    return ops * (double)size / (1024 * 1024) / sw.Elapsed.TotalSeconds;
}
