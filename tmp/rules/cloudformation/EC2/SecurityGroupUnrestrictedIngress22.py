from AbsSecurityGroupUnrestrictedIngressCustom import \
    AbsSecurityGroupUnrestrictedIngressCustom

class SecurityGroupUnrestrictedIngress22(AbsSecurityGroupUnrestrictedIngressCustom):
    def __init__(self):
        super().__init__(check_id="CKV_AWS_331", port=22)


check = SecurityGroupUnrestrictedIngress22()
