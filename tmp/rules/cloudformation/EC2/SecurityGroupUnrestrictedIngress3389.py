from AbsSecurityGroupUnrestrictedIngressCustom import \
    AbsSecurityGroupUnrestrictedIngressCustom

class SecurityGroupUnrestrictedIngress3389(AbsSecurityGroupUnrestrictedIngressCustom):
    def __init__(self):
        super().__init__(check_id="CKV_AWS_261", port=3389)


check = SecurityGroupUnrestrictedIngress3389()
