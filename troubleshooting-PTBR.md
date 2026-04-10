# Guia de Resolução de Problemas (Troubleshooting)

É comum que práticas de endurecimento (*Hardening*) em prol de eficiência máxima de segurança acabem quebrando a conveniência de alguns processos habituais do Windows. Este guia resume métodos rápidos para restaurar itens e serviços sem precisar desligar a segurança de toda a sua máquina.

---

### 1. Perda de Aplicativos e Jogos associados ao Xbox
**A Causa:** O Passo 1 do Hardening remove rastreadores base e as integrações vitais do pacote `NetApiSvc` do Xbox para conter pontos de acesso na máquina.

**A Restauração:**
No PowerShell aberto em modo **Administrador**, altere a inicialização para manual e levante os serviços cruciais executando:
```powershell
Set-Service -Name "XblGameSave" -StartupType Manual
Set-Service -Name "XboxNetApiSvc" -StartupType Manual
Start-Service -Name "XblGameSave"
```

---

### 2. Redes e Impressoras ou Sistemas NAS falhando em conectar
**A Causa:** Bloqueio severo do protocolo `SMBv1` executado no Passo 2 (uma das maiores vulnerabilidades históricas em redes Windows e o principal alvo de ramsonwares).

**A Restauração:**
Reverter os protocolos SMBv1 colocará sua rede sob constante ameaça de varredura. Aplique isto apenas no caso extremo no qual exija-se conexão a dispositivos jurássicos corporativos da década passada:
```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -Force
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All
```

---

### 3. A ausência de alertas visuais ou pastas abrindo ao plugar PenDrives
**A Causa:** O clássico `Autorun` e o `AutoPlay` foram apagados via registro por segurança no Passo 13. O computador deixou de inferir sozinho a natureza que foi plugada dentro do chassi à revelia do usuário.

**A Restauração:**
O dispositivo sempre estará utilizável bastando utilizar um acesso pelo atalho `Win + E` (Explorador de Arquivos) logo após o uso. Se a conveniência automática for inegociável na rotina por conta de fluxos visuais em estações limitadas, reverta completamente via:
```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 0 -Type DWord
```

---

### 4. Entraves temporários de acesso de login bloqueando senha
**A Causa:** Limitador executado no Passo 4. Trata-se do fator *Identidade* que definiu o `LockoutBadCount = 5` contra invasões de *Brute Force*.

**A Restauração:**
Caso se perca no login, o sistema entra em quarentena forçada. A regra foi traçada para perdurar exatos 15 minutos e limpar os apontamentos. Resta aguardar a queda natural por contagem da placa em vez de tentar reinicializações que irritam e reescrevem o status da trava local.

---

### 5. Navegadores recusam conectividade em bases Wi-Fi específicas
**A Causa:** Foi efetuado o direcionamento persistente de DNS seguro via Cloudflare (`1.1.1.1`) no Passo 8, impedindo modems específicos em redes locais e fechadas de rastrear ou assumir conexões.

**A Restauração:**
Se a internet via cabo ou o provedor DHCP apresentar a trava amarela no Windows, resete o fornecimento para obter os credenciamentos da placa em nuvem automaticamente:
```powershell
Get-NetAdapter | Where-Object Status -eq "Up" | Set-DnsClientServerAddress -ResetServerAddresses
```

---

> **Nota Adicional:** Para uma reversão completa de todas as 13 configurações, consulte o guia passo a passo em `Troubleshooting.md`.
