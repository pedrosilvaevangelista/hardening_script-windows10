# 🛡️ Scripts de Hardening para Windows 10

Um conjunto completo de scripts PowerShell para aplicar e verificar configurações de segurança (hardening) em estações de trabalho Windows 10.

## 📋 Conteúdo

- **`hardening-win10.ps1`** - Script principal que aplica as configurações de segurança
- **`hardening-check.ps1`** - Script de verificação que confirma se as configurações foram aplicadas corretamente

## ⚡ Execução Rápida

```powershell
# 1. Aplicar hardening
.\hardening-win10.ps1

# 2. Verificar configurações
.\hardening-check.ps1
```

## 🔧 hardening-win10.ps1

### O que faz?

Este script aplica **10 categorias principais** de configurações de segurança:

#### 1. 🛑 Desativa Serviços Desnecessários
- **Xbox** (XblGameSave, XboxNetApiSvc, XboxGipSvc)
- **Telemetria** (DiagTrack, dmwappushservice)
- **Mídia** (WMPNetworkSvc)
- **Outros** (RemoteRegistry, Fax, RetailDemo, WerSvc, MapsBroker, SharedAccess, TrkWks, PhoneSvc)

#### 2. 🚫 Remove SMBv1 (Protocolo Vulnerável)
- Desabilita cliente e servidor SMBv1
- Força assinatura de segurança SMB
- Remove recursos SMBv1 do Windows

#### 3. 🔄 Configura Windows Update
- Ativa download e instalação automáticos
- Impede reinicialização automática com usuários logados

#### 4. 🔐 Políticas de Senha Forte
- **Comprimento mínimo:** 12 caracteres
- **Validade:** 90 dias
- **Histórico:** 24 senhas anteriores
- **Bloqueio:** 5 tentativas → trava por 15 minutos
- **Complexidade:** Ativada via secedit

#### 5. 🔥 Windows Firewall
- Ativa proteção em **todos os perfis** (Domínio, Privado, Público)
- Habilita logs de conexões permitidas e bloqueadas

#### 6. 🛑 UAC (Controle de Conta de Usuário)
- Força confirmação para administradores
- Solicita credenciais para usuários padrão
- Mantém UAC sempre ativo

#### 7. 📜 Auditoria de Eventos
- **Login/Logout** (sucesso e falha)
- **Bloqueio de conta**
- **Gerenciamento de usuários**
- **Criação de processos**
- **Eventos do sistema**

#### 8. 🛡️ Windows Defender
- Proteção em tempo real sempre ativa
- Verificação diária às **02:00**
- Relatórios MAPS avançados
- Envio automático de amostras suspeitas

#### 9. ⚙️ Configurações Extras de Segurança
- **LM Hash desabilitado** (evita ataques de hash)
- **Timeout de inatividade:** 15 minutos
- **AutoRun desligado** (pen drives não executam automaticamente)
- **Windows Script Host desabilitado** (bloqueia .vbs, .js)

#### 10. 💻 PowerShell Execution Policy
- Define como **RemoteSigned** (só executa scripts locais ou assinados)

### Pré-requisitos

- Windows 10
- **Executar como Administrador** (obrigatório)
- PowerShell 5.0 ou superior

### Como usar

```powershell
# Clone ou baixe o script
# Abra PowerShell como Administrador
# Execute:
.\hardening-win10.ps1
```

### Saída esperada

```
[INFO] Iniciando processo de hardening do Windows 10...
[SUCESSO] Serviço RemoteRegistry desativado
[SUCESSO] SMBv1 desabilitado com sucesso
[SUCESSO] Windows Update configurado
[SUCESSO] Politicas de senha configuradas
[SUCESSO] Windows Firewall configurado e ativado
[SUCESSO] UAC configurado
[SUCESSO] Auditoria configurada
[SUCESSO] Windows Defender configurado
[SUCESSO] Configuracoes de seguranca adicionais aplicadas
[SUCESSO] PowerShell Execution Policy configurada

[AVISO] IMPORTANTE: Reinicie o sistema para que todas as alteracoes tenham efeito completo.
[INFO] Processo de hardening concluido!

Deseja reiniciar o sistema agora? (S/N)
```

---

## 🔍 hardening-check.ps1

### O que faz?

Script de **verificação e auditoria** que confirma se todas as configurações de hardening foram aplicadas corretamente.

### Verificações realizadas

#### ✅ Status dos Serviços
- Confirma se todos os serviços listados estão **desativados** e **parados**

#### 🛡️ Configurações SMB
- Verifica assinatura obrigatória no cliente e servidor
- Confirma desabilitação do recurso SMBv1

#### 🔄 Windows Update
- Checa configuração de instalação automática
- Verifica política de reinicialização

#### 🔐 Políticas de Senha
- Valida comprimento mínimo (≥12 caracteres)
- Confirma limite de tentativas (≤5)
- Verifica desabilitação do LM Hash

#### 🔥 Windows Firewall
- Confirma ativação em todos os perfis
- Verifica configuração de logs

#### 🛑 UAC
- Valida configurações para administradores e usuários
- Confirma que UAC está habilitado

#### 📜 Auditoria
- Verifica se todas as categorias de auditoria estão ativas
- Confirma logs de sucesso e falha

#### 🛡️ Windows Defender
- Confirma proteção em tempo real
- Verifica configurações de relatórios e amostras
- Checa status geral do antivírus

#### ⚙️ Configurações Extras
- Timeout de inatividade
- AutoRun desabilitado
- Windows Script Host bloqueado

#### 💻 PowerShell
- Confirma Execution Policy como RemoteSigned

### Como usar

```powershell
# Após executar o hardening-win10.ps1
# Execute a verificação:
.\hardening-check.ps1
```

### Saída esperada

```
============================================================
1. VERIFICACAO DE SERVICOS DESATIVADOS
============================================================
[OK] Servico RemoteRegistry esta desativado
[OK] Servico DiagTrack esta desativado
[INFO] Servico Fax nao existe neste sistema

============================================================
RELATORIO FINAL DE VERIFICACAO
============================================================
[INFO] Total de verificacoes: 45
[OK] Verificacoes aprovadas: 42
[AVISO] Verificacoes com aviso: 2
[FALHA] Verificacoes reprovadas: 1
[INFO] Taxa de sucesso: 93.3%

[OK] PARABENS! Todas as configuracoes de seguranca essenciais estao aplicadas!
```

### Códigos de Status

- **[OK]** 🟢 - Configuração aplicada corretamente
- **[AVISO]** 🟡 - Configuração parcial ou requer atenção
- **[FALHA]** 🔴 - Configuração não aplicada ou incorreta
- **[INFO]** 🔵 - Informação adicional

---

## ⚠️ Impactos e Considerações

### 🎮 Jogos e Xbox
- **Serviços Xbox desativados** → Jogos e recursos Xbox podem não funcionar
- **Solução:** Reative manualmente se necessário

### 📡 Rede e Dispositivos Legados
- **SMBv1 desabilitado** → Impressoras antigas, NAS antigos podem parar de funcionar
- **Firewall restritivo** → Alguns aplicativos podem precisar de regras manuais
- **Solução:** Configure exceções específicas ou atualize dispositivos

### 🔒 Usabilidade
- **UAC sempre ativo** → Mais prompts de confirmação
- **Políticas de senha rigorosas** → Senhas complexas obrigatórias
- **AutoRun desligado** → Pen drives não executam automaticamente
- **Scripts bloqueados** → Arquivos .vbs/.js não executam

### 📊 Desempenho
- **Auditoria ativa** → Logs detalhados (pode consumir espaço em disco)
- **Windows Defender** → Verificação diária às 2h (pode afetar desempenho)

### 🔄 Reinicialização
- **Obrigatória** → Algumas configurações só funcionam após restart

---

## 🚀 Guia de Uso

### 1. Preparação
```powershell
# Baixe os scripts
# Abra PowerShell como Administrador
# Navegue até a pasta dos scripts
cd C:\caminho\para\scripts
```

### 2. Execução do Hardening
```powershell
# Execute o hardening
.\hardening-win10.ps1

# Quando solicitado, reinicie o sistema
```

### 3. Verificação
```powershell
# Após reiniciar, execute a verificação
.\hardening-check.ps1

# Opcional: Salve o relatório
# O script perguntará se deseja salvar em arquivo
```

### 4. Interpretação dos Resultados

#### Taxa de Sucesso
- **90-100%** 🟢 Excelente - Sistema bem protegido
- **75-89%** 🟡 Bom - Algumas melhorias necessárias  
- **<75%** 🔴 Ruim - Execute o hardening novamente

---

## 🎯 Cenários de Uso

### 🏢 Ambiente Corporativo
- **Recomendado:** Execute em todos os computadores
- **Benefícios:** Conformidade com políticas de segurança
- **Cuidados:** Teste em grupo piloto primeiro

### 🏠 Uso Pessoal
- **Avalie:** Algumas restrições podem ser inconvenientes
- **Personalize:** Desative políticas de senha muito rigorosas se necessário
- **Benefícios:** Proteção extra contra malware

### 🧪 Ambiente de Teste
- **Perfeito:** Para validar configurações antes da produção
- **Use:** Script de verificação para auditorias

---

## 🆘 Solução de Problemas

### Erro: "Script precisa ser executado como Administrador"
```powershell
# Clique com botão direito no PowerShell
# Selecione "Executar como administrador"
```

### Erro: "Execution Policy"
```powershell
# Execute temporariamente:
Set-ExecutionPolicy Bypass -Scope Process -Force
.\hardening-win10.ps1
```

### Dispositivos antigos param de funcionar
```powershell
# Para reativar SMBv1 (NÃO RECOMENDADO):
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client"
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server"
```

### Reverter configurações
- Não há script de reversão automática
- Use `gpedit.msc` ou `regedit` para alterações manuais
- Restaure backup do sistema se disponível

---

## 📋 Checklist de Validação

Após executar ambos os scripts, confirme:

- [ ] Taxa de sucesso > 90%
- [ ] Nenhuma falha crítica nos serviços essenciais
- [ ] Dispositivos de rede funcionando
- [ ] Aplicações críticas funcionando
- [ ] Backup do sistema criado (recomendado)

---

## 📚 Referências

- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [CIS Benchmarks for Windows 10](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## 📄 Licença

Scripts fornecidos para fins educacionais e de segurança. Teste sempre em ambiente controlado antes de aplicar em produção.

---

## 🤝 Contribuições

Sugestões de melhorias são bem-vindas! Lembre-se de:
- Testar em ambiente isolado
- Documentar mudanças
- Manter compatibilidade com Windows 10

---

**⚠️ IMPORTANTE:** Sempre faça backup do sistema antes de aplicar hardening em produção!
