#[test]
fn test_mixed_character_pins() {
    use pinpam_core::{pin::Pin, pinpolicy::PinPolicy};
    
    let policy = PinPolicy {
        min_length: 6,
        max_length: Some(16),
        max_attempts: 5,
        pinutil_path: "/usr/bin/pinutil".into(),
        tcti: None,
    };
    
    // 应该通过的测试
    assert!(Pin::new("123456", &policy).is_ok(), "纯数字应该可以");
    assert!(Pin::new("abc123", &policy).is_ok(), "字母+数字应该可以");
    assert!(Pin::new("MyP@ss!", &policy).is_ok(), "混合+符号应该可以");
    assert!(Pin::new("hunter2", &policy).is_ok(), "纯字母应该可以");
    assert!(Pin::new("P@ssw0rd123", &policy).is_ok(), "强密码应该可以");
    assert!(Pin::new("!!!###", &policy).is_ok(), "纯符号应该可以");
    
    // 应该失败的测试
    assert!(Pin::new("", &policy).is_err(), "空字符串应该失败");
    assert!(Pin::new("12345", &policy).is_err(), "太短应该失败");
    assert!(Pin::new("12345678901234567", &policy).is_err(), "太长应该失败");
    
    println!("✅ 所有测试通过！现在 pinpam 支持混合字符了");
}
