def type_number_from_string(string):
    match(string):
        case "A":
            return 1
        case "NS":
            return 2
        case "CNAME":
            return 5
        case "MX":
            return 15
        case "TXT":
            return 16
        case "AAAA":
            return 28
    return -1

def type_number_to_string(qtype):
    match(qtype):
        case 1:
            return "A"
        case 2:
            return "NS"
        case 5:
            return "CNAME"
        case 15:
            return "MX"
        case 16:
            return "TXT"
        case 28:
            return "AAAA"
    return -1

def response_code_to_number(string):
    match(string):
        case "NOERROR":
            return 0
        case "FORMERR":
            return 1
        case "SERVFAIL":
            return 2
        case "NXDOMAIN":
            return 3
        case "NOTIMP":
            return 4
        case "REFUSED":
            return 5
    return -1