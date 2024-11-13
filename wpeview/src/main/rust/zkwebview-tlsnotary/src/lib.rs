pub mod zkwebview-tlsnotary;
extern crate jni;

use crate::zkwebview-tlsnotary::prove;
use jni::objects::{JClass, JString};
use jni::JNIEnv;

#[no_mangle]
pub extern "C" fn Java_com_macmac_rust_1jni_RustLib_prove(
    mut env: JNIEnv,
    _class: JClass,
    hosted_notary: JString,
    domain: JString,
    uri: JString,
) {
    let hosted_notary_str: String = env.get_string(&hosted_notary).unwrap().into();
    let domain_str: String = env.get_string(&domain).unwrap().into();
    let uri_str: String = env.get_string(&uri).unwrap().into();
    if let Err(e) = prove(hosted_notary_str, domain_str, uri_str) {
        println!("{}", e); // "There is an error: Oops"
    }
}
