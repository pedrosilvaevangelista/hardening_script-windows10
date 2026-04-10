# Windows 10 Hardening

Um script PowerShell focado em reduzir drasticamente a superfície de ataque de instâncias Windows 10, elevando a postura de segurança e privacidade com base em frameworks reconhecidos internacionalmente (**NIST** e **CIS**).

## Objetivo

Transformar uma configuração padrão (focada em conveniência e integração excessiva) em um ambiente sólido e rigoroso, mitigando vulnerabilidades comuns, restringindo vetores ransomware via rede/USB e eliminando espionagem de dados.

---

## Controles de Segurança Aplicados

O script implementa os seguintes controles críticos de arquitetura:

1. **Serviços Limpos**
   Desabilita serviços de risco e monitoramentos indesejados (`RemoteRegistry`, Fax, `DiagTrack`, `MapsBroker`).
2. **Fim do SMBv1**
   Protege contra invasões severas de rede (ex: WannaCry) desabilitando protocolos defasados em definitivo.
3. **Restrição do Windows Update**
   Configura limites para as notificações, forçando instalações importantes mas impedindo reinicializações forçadas surpresas.
4. **Política de Senhas Intensa**
   Exige 12 caracteres, complexidade matemática e bloqueio brutal contra ataques forçados (15 minutos de pane após 5 erros).
5. **Firewall Universal**
   Fixa compulsoriamente as regras vitais do Firewall para os perfis Domínio, Particular e Público em `Ativado`.
6. **Corte na Automação WSH**
   Remove as capacidades nativas do Windows de executar scripts invisivelmente (como `.vbs` e `.js` muitas vezes disparados via e-mail).
7. **UAC em Alerta Máximo**
   Isola a barreira diária de privilégios rodando autorizações unicamente na tela blindada do SO (*Secure Desktop*).
8. **DNS Hardened Server**
   Redireciona seu tráfego vital para as pontes `1.1.1.1` (Cloudflare) para inviabilizar rastreamento cego do provedor.
9. **Barreira Exploit (DEP/ASLR)**
   Liga a randomização complexa ao Kernel para fechar rotas de exploração zero-day (ataques desconhecidos).
10. **Acesso Oculto Revelado**
    Exige em tela as extensões verdadeiras para prevenir uso de ferramentas disfarçadas (como um executável que se passa por PDF).
11. **Supervisão do PowerShell**
    Acende holofotes totais de auditoria, rastreando palavras-chave no *Event Viewer* caso um vírus tente rodar um terminal escondido.
12. **Telemetria Extirpada**
    Obriga silenciosamente os serviços de coleta de diagnóstico da Microsoft a zerarem remessas de coleta de política de uso de dados.
13. **AutoRun Erradicado**
    Extingue opções nativas de execução de pendrives e mídias visíveis a fim de erradicar infecção de drives físicos.

---

## Como Utilizar

Todos os comandos abaixo devem ser executados no **PowerShell como Administrador**.

---

### 🔒 Aplicar o Hardening

A execução baseia-se num modelo de **Auditoria**. Nada é implementado sem antes autorizar os alertas interativos no terminal (`Y/N`).

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pedrosilvaevangelista/hardening_script-windows10/main/hardening-win10.ps1'))
```

> **Aviso Importante:** Recomendamos reiniciar a máquina logo após a conclusão para as diretrizes de registro serem assimiladas no Kernel de maneira uniforme.

---

### ✅ Verificar o Hardening

Executa os testes automatizados (Pester) para validar se todos os 13 controles de segurança estão corretamente aplicados na máquina. Requer o módulo [Pester](https://pester.dev) (`Install-Module Pester -Force`).

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pedrosilvaevangelista/hardening_script-windows10/main/hardening-win10.tests.ps1'))
```

---

### ↩️ Desfazer o Hardening

Reverte todas as configurações de segurança aplicadas pelo script, restaurando os padrões originais do Windows 10. Cada etapa solicita confirmação antes de reverter.

> **Atenção:** Desfazer o hardening reduz significativamente a postura de segurança do sistema.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pedrosilvaevangelista/hardening_script-windows10/main/rollback-win10.ps1'))
```
