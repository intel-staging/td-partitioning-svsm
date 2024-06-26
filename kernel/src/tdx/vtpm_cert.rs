// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate alloc;

use super::{
    attestation::quote_generation,
    error::TdxError,
    measurement::{hash_sha1, hash_sha384},
};
use crate::{
    crypto::x509::{
        AlgorithmIdentifier, AuthorityKeyIdentifier, CertificateBuilder, DistinguishedName,
        EcdsaSignatureDer, Extension, SubjectAltName, X509Error,
    },
    tcg2::{TPM2_SHA1_SIZE, TPM2_SHA384_SIZE},
    types::PAGE_SIZE,
    vtpm::{
        capability::tpm_property,
        ecdsa::{create_ecdsa_signing_key, ecdsa_sign, EcdsaSigningKey},
        ek::{create_tpm_ek, provision_ca_cert, provision_ek_cert},
    },
};
use alloc::{vec, vec::Vec};
use der::{
    asn1::{BitString, ObjectIdentifier, OctetString, SetOfVec, UIntBytes, Utf8String},
    Any, Encodable, Tag,
};

pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.19");
pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.15");
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.35");
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");
pub const VTPMTD_CA_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.5");
pub const EXTNID_VTPMTD_QUOTE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.2");
pub const EXTNID_VTPMTD_EVENT_LOG: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.3");
pub const TCG_EK_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new("2.23.133.8.1");

// As specified in https://datatracker.ietf.org/doc/html/rfc5480#appendix-A
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//     iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
// }
pub const ID_EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
// secp384r1 OBJECT IDENTIFIER ::= {
//     iso(1) identified-organization(3) certicom(132) curve(0) 34
// }
pub const SECP384R1_OID: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");

pub const ID_EC_SIG_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.3");

const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.29.17");
const TCG_TPM_MANUFACTURER: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.1");
const TCG_TPM_MODEL: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.2");
const TCG_TPM_VERSION: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.3");

pub fn generate_vtpm_certificates(event_log: &[u8]) -> Result<(), TdxError> {
    let ek_pub = create_tpm_ek().map_err(|_| TdxError::VtpmCertificates)?;
    let ecdsa_keypair = create_ecdsa_signing_key().map_err(|_| TdxError::VtpmCertificates)?;

    let mut quote_buf = alloc::vec![0u8; PAGE_SIZE * 2];
    let mut ecdsa_pub_sha384 = [0u8; TPM2_SHA384_SIZE];
    hash_sha384(ecdsa_keypair.public_key.as_slice(), &mut ecdsa_pub_sha384)?;

    let td_quote_len =
        quote_generation(&ecdsa_pub_sha384, &mut quote_buf).map_err(|_| TdxError::Attestation)?;
    let td_quote = &quote_buf[..td_quote_len];

    // create ca cert
    let ca_cert = generate_ca_cert(td_quote, event_log, &ecdsa_keypair)
        .map_err(|_| TdxError::VtpmCertificates)?;

    // create ek cert
    let ek_cert = generate_ek_cert(ek_pub.as_slice(), &ecdsa_keypair)
        .map_err(|_| TdxError::VtpmCertificates)?;

    // Provision CA and EK certificate into TPM NV
    provision_ca_cert(&ca_cert).map_err(|_| TdxError::VtpmCertificates)?;
    provision_ek_cert(&ek_cert).map_err(|_| TdxError::VtpmCertificates)?;

    Ok(())
}

fn generate_ca_cert(
    td_quote: &[u8],
    event_log: &[u8],
    ecdsa_keypair: &EcdsaSigningKey,
) -> Result<Vec<u8>, X509Error> {
    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };

    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };

    // extended key usage
    let eku: Vec<ObjectIdentifier> = vec![VTPMTD_CA_EXTENDED_KEY_USAGE];
    let eku = eku.to_vec().map_err(X509Error::DerEncoding)?;

    // basic constrains
    let basic_constrains: Vec<bool> = vec![true];
    let basic_constrains = basic_constrains.to_vec().map_err(X509Error::DerEncoding)?;

    let mut x509_certificate =
        CertificateBuilder::new(sig_alg, algorithm, &ecdsa_keypair.public_key, true)?;
    // 1970-01-01T00:00:00Z
    x509_certificate.set_not_before(core::time::Duration::new(0, 0))?;
    // 9999-12-31T23:59:59Z
    x509_certificate.set_not_after(core::time::Duration::new(253402300799, 0))?;

    x509_certificate.add_extension(Extension::new(
        BASIC_CONSTRAINTS,
        Some(true),
        Some(basic_constrains.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        EXTENDED_KEY_USAGE,
        Some(false),
        Some(eku.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        EXTNID_VTPMTD_QUOTE,
        Some(false),
        Some(td_quote),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        EXTNID_VTPMTD_EVENT_LOG,
        Some(false),
        Some(event_log),
    )?)?;
    let signature = certificate_sign(&x509_certificate, ecdsa_keypair)?;
    x509_certificate.set_signature(&signature)?;
    let res = x509_certificate.build();

    res.to_vec().map_err(X509Error::DerEncoding)
}

fn generate_ek_cert(ek_pub: &[u8], ecdsa_keypair: &EcdsaSigningKey) -> Result<Vec<u8>, X509Error> {
    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };

    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };

    // basic constrains
    let basic_constrains: Vec<bool> = vec![false];
    let basic_constrains = basic_constrains.to_vec().map_err(X509Error::DerEncoding)?;

    // extended key usage
    let eku: Vec<ObjectIdentifier> = vec![TCG_EK_CERTIFICATE];
    let eku = eku.to_vec().map_err(X509Error::DerEncoding)?;

    // authority key identifier
    let auth_key_identifier = gen_auth_key_identifier(ek_pub)?;

    // follow ek-credential spec Section 3.2.
    // keyAgreement (4) refers to https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    let ku = BitString::new(0, &[0x08]).map_err(X509Error::DerEncoding)?;
    let ku = ku.to_vec().map_err(X509Error::DerEncoding)?;

    // subject alt name
    let subject_alt_name = gen_subject_alt_name()?;

    let mut x509_certificate = CertificateBuilder::new(sig_alg, algorithm, ek_pub, false)?;
    // 1970-01-01T00:00:00Z
    x509_certificate.set_not_before(core::time::Duration::new(0, 0))?;
    // 9999-12-31T23:59:59Z
    x509_certificate.set_not_after(core::time::Duration::new(253402300799, 0))?;
    x509_certificate.add_extension(Extension::new(
        BASIC_CONSTRAINTS,
        Some(true),
        Some(basic_constrains.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        AUTHORITY_KEY_IDENTIFIER,
        Some(false),
        Some(auth_key_identifier.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(KEY_USAGE, Some(true), Some(ku.as_slice()))?)?;
    x509_certificate.add_extension(Extension::new(
        EXTENDED_KEY_USAGE,
        Some(false),
        Some(eku.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        SUBJECT_ALT_NAME,
        Some(true),
        Some(subject_alt_name.as_slice()),
    )?)?;
    let signature = certificate_sign(&x509_certificate, ecdsa_keypair)?;
    x509_certificate.set_signature(&signature)?;
    let res = x509_certificate.build();

    res.to_vec().map_err(X509Error::DerEncoding)
}

fn gen_auth_key_identifier(ek_pub: &[u8]) -> Result<Vec<u8>, X509Error> {
    // authority key identifier
    let mut ek_pub_sha1 = [0u8; TPM2_SHA1_SIZE];
    let _ = hash_sha1(ek_pub, &mut ek_pub_sha1).map_err(|_| X509Error::CalculateHash);

    let pub_sha1 = OctetString::new(ek_pub_sha1.as_ref()).map_err(X509Error::DerEncoding)?;
    let auth_key_identifier: AuthorityKeyIdentifier<'_> = AuthorityKeyIdentifier(pub_sha1);
    let auth_key_identifier = vec![auth_key_identifier];
    auth_key_identifier.to_vec().map_err(X509Error::DerEncoding)
}

fn gen_subject_alt_name() -> Result<Vec<u8>, X509Error> {
    let tpm2_caps = tpm_property().expect("Failed to get TPM properties");

    let mut tcg_tpm_manufaturer = SetOfVec::new();
    let mut manufacturer = Vec::new();
    manufacturer.extend_from_slice(&tpm2_caps.manufacturer.to_be_bytes());
    let _ = tcg_tpm_manufaturer.add(DistinguishedName {
        attribute_type: TCG_TPM_MANUFACTURER,
        value: Utf8String::new(manufacturer.as_slice()).unwrap().into(),
    });

    let mut tcg_tpm_model = SetOfVec::new();
    let mut model = Vec::new();
    model.extend_from_slice(&tpm2_caps.vendor_1.to_be_bytes());
    model.extend_from_slice(&tpm2_caps.vendor_2.to_be_bytes());
    model.extend_from_slice(&tpm2_caps.vendor_3.to_be_bytes());
    model.extend_from_slice(&tpm2_caps.vendor_4.to_be_bytes());
    let _ = tcg_tpm_model.add(DistinguishedName {
        attribute_type: TCG_TPM_MODEL,
        value: Utf8String::new(model.as_slice()).unwrap().into(),
    });

    let mut tcg_tpm_version = SetOfVec::new();
    let mut version = Vec::new();
    version.extend_from_slice(&tpm2_caps.version_1.to_be_bytes());
    version.extend_from_slice(&tpm2_caps.version_2.to_be_bytes());
    let _ = tcg_tpm_version.add(DistinguishedName {
        attribute_type: TCG_TPM_VERSION,
        value: Utf8String::new(version.as_slice()).unwrap().into(),
    });

    let sub_alt_name = vec![tcg_tpm_manufaturer, tcg_tpm_model, tcg_tpm_version];
    let sub_alt_name: SubjectAltName<'_> = SubjectAltName(sub_alt_name);
    let sub_alt_name = vec![sub_alt_name];
    sub_alt_name.to_vec().map_err(X509Error::DerEncoding)
}

fn certificate_sign(
    cert: &CertificateBuilder<'_>,
    key: &EcdsaSigningKey,
) -> Result<Vec<u8>, X509Error> {
    let mut digest = [0u8; TPM2_SHA384_SIZE];
    let tbs_der = cert
        .build()
        .tbs_certificate
        .to_vec()
        .map_err(X509Error::DerEncoding)?;
    hash_sha384(&tbs_der, &mut digest).map_err(|_| X509Error::CalculateHash)?;
    let (r, s) = ecdsa_sign(key, &digest[..]).map_err(|_| X509Error::SignCertificate)?;
    EcdsaSignatureDer {
        r: UIntBytes::new(&r).map_err(X509Error::DerEncoding)?,
        s: UIntBytes::new(&s).map_err(X509Error::DerEncoding)?,
    }
    .to_vec()
    .map_err(X509Error::DerEncoding)
}
