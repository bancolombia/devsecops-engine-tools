CYBEARK_TENABLE_SEGMENTS = ['10.60.5.80/28','10.8.146.208/28','10.123.176.0/21','10.8.146.208/28','10.72.136.0/25','10.60.5.80/28','10.8.47.5/32','10.8.47.6/32','{{resolve:ssm:RangoIpCyberarkAWS:1}}','{{resolve:ssm:RangoIpCyberarkNiquia:1}}','{{resolve:ssm:RangoIpHerramientasSeguridad:2}}']

def verified_listValues(listPosValues, listValue):

    if(len(listValue)>1 and "no" in listValue):
        return False
    else:
        for clv in listValue:
            if clv not in listPosValues:
                return False

    return True

def verified_tag(tagname):
    return ["bancolombia:"+tagname, "banistmo:"+tagname]