﻿using AppControlManager.SiPolicy;
using System;
using System.Collections.Generic;

namespace AppControlManager.SiPolicyIntel
{
    internal sealed class PublisherSignerRuleComparer : IEqualityComparer<SignerRule>
    {
        public bool Equals(SignerRule? x, SignerRule? y)
        {
            if (x is null || y is null)
            {
                return false;
            }

            // First check: SSType and Authorization must be equal
            if (x.SigningScenario != y.SigningScenario || x.Auth != y.Auth)
            {
                return false;
            }

            Signer signerX = x.SignerElement;
            Signer signerY = y.SignerElement;

            // Rule 1: Check if Name, CertRoot.Value, and CertPublisher.Value are equal
            // For intermediate certificate type that uses full proper chain in signer
            if (IsSignerRule1Match(signerX, signerY))
            {
                return true;
            }

            // Rule 2: Check if Name and CertRoot.Value are equal
            // For PCA/Root/Leaf certificate signer types
            if (IsSignerRule2Match(signerX, signerY))
            {
                return true;
            }

            // If none of the rules match, the SignerRule objects are not equal
            return false;
        }

        public int GetHashCode(SignerRule obj)
        {
            ArgumentNullException.ThrowIfNull(obj);

            Signer signer = obj.SignerElement;
            long hash = 17;  // Start with an initial value

            const long modulus = 0x7FFFFFFF; // Max value for int

            // First: Include SSType and Authorization in the hash calculation
            hash = (hash * 31 + obj.SigningScenario.GetHashCode()) % modulus;
            hash = (hash * 31 + obj.Auth.GetHashCode()) % modulus;

            // Rule 1: Use Name, CertRoot.Value, and CertPublisher.Value for hash calculation
            if (!string.IsNullOrWhiteSpace(signer.Name))
            {
                hash = (hash * 31 + signer.Name.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
            }

            if (signer.CertRoot?.Value != null)
            {
                hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(signer.CertRoot.Value)) % modulus;
            }

            if (!string.IsNullOrWhiteSpace(signer.CertPublisher?.Value))
            {
                hash = (hash * 31 + signer.CertPublisher.Value.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
            }

            // Rule 2: Use Name and CertRoot.Value for hash calculation
            if (!string.IsNullOrWhiteSpace(signer.Name))
            {
                hash = (hash * 31 + signer.Name.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
            }

            if (signer.CertRoot?.Value != null)
            {
                hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(signer.CertRoot.Value)) % modulus;
            }

            return (int)(hash & 0x7FFFFFFF); // Ensure non-negative hash value
        }


        /// <summary>
        /// Rule 1: Name, CertRoot.Value, CertPublisher.Value must match
        /// </summary>
        /// <param name="signerX"></param>
        /// <param name="signerY"></param>
        /// <returns></returns>
        private static bool IsSignerRule1Match(Signer signerX, Signer signerY)
        {
            return !string.IsNullOrWhiteSpace(signerX.Name) &&
                   !string.IsNullOrWhiteSpace(signerY.Name) &&
                   string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
                   BytesArrayComparer.AreByteArraysEqual(signerX.CertRoot?.Value, signerY.CertRoot?.Value) &&
                   string.Equals(signerX.CertPublisher?.Value, signerY.CertPublisher?.Value, StringComparison.OrdinalIgnoreCase);
        }


        /// <summary>
        /// Rule 2: Name and CertRoot.Value must match
        /// </summary>
        /// <param name="signerX"></param>
        /// <param name="signerY"></param>
        /// <returns></returns>
        private static bool IsSignerRule2Match(Signer signerX, Signer signerY)
        {
            return !string.IsNullOrWhiteSpace(signerX.Name) &&
                   !string.IsNullOrWhiteSpace(signerY.Name) &&
                   string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
                   BytesArrayComparer.AreByteArraysEqual(signerX.CertRoot?.Value, signerY.CertRoot?.Value);
        }

    }
}
