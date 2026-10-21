Relatório de prontidão do SecureCorpPortal
Escrito para: você, como responsável técnico pelo laboratório antes da publicação no GitHub.

Não modifiquei nenhum arquivo do repositório. Fiz três verificações não destrutivas:

Clone limpo: clonei o repositório para o scratchpad e tentei compilar.
Pacotes: rodei dotnet list package --vulnerable e --deprecated.
Testes: rodei dotnet test com roll-forward para o .NET 10.
Não executei nenhuma varredura nem ataque.

A. Executive Summary
O código é sólido para um laboratório educacional.

Defesas verificadas no código:
Política de acesso por padrão (fallback policy) exigindo autenticação.
Autorização por recurso centralizada em DocumentAccessPolicy.
DTOs explícitos, sem mass assignment.
Upload com allowlist, assinatura binária e nome GUID, fora de wwwroot.
CSRF no MVC, CSP restritiva, logs JSON com correlação.
Nenhuma injeção SQL encontrada: não há SQL manual, só LINQ.
Nenhum Html.Raw nas views.
Nenhum SSRF, command injection ou path traversal explorável: não existe HttpClient, Process.Start nem caminho montado a partir de entrada do usuário.
Existe um impedimento que invalida a publicação como está. O .gitignore exclui src/SecureCorpPortal/Data/ e o commit não contém esse diretório. Verifiquei de três formas:

git check-ignore -v aponta .gitignore:27.
git ls-files não lista nenhum arquivo de Data/.
Um clone limpo falha com CS0234: namespace 'Data' não existe.
Quem clonar o repositório não consegue compilar nem subir o Docker. A causa é data/ (linhas 26–27) combinada com core.ignorecase=true no Windows.

Lacunas funcionais para o laboratório:

Não há rate limiting nem HTTPS/HSTS.
Não há fluxo de recuperação de senha, MFA ou módulos de laboratório.
Oito documentos referenciados no README e nos comentários do código não existem.
Não pude confirmar a suíte de testes: o ambiente local só tem o runtime .NET 10 (veja a seção G).
B. Security Findings
Classificação: [C] confirmado no código; [P] potencial, exige validação dinâmica; [D] falha de documentação ou processo.

ID	Vulnerabilidade	Sev.	Evidência	Componente	Recomendação
F-01 [C]	Diretório Data/ fora do Git (AppDbContext, Seeder, Initializer, DemoAccounts). O repositório não compila após clonar	Crítica (bloqueia a publicação)	.gitignore:26-27; clone limpo falha com CS0234	Repositório	Ancorar com /data/, rodar git add src/SecureCorpPortal/Data e validar com um novo clone e docker build
F-02 [C]	Sem rate limiting em nenhum endpoint. O lockout é só por conta, então não há proteção contra password spraying. Qualquer usuário conhecido pode ser bloqueado de propósito (CWE-307/645)	Média	Program.cs:62-74 (sem UseRateLimiter); ServiceCollectionExtensions.cs:58-59	Login, registro, API	AddRateLimiter por IP em /login, /register, /api/auth/* e no upload
F-03 [C]	O logout não invalida a sessão no servidor. O cookie é stateless e LogoutAsync só chama SignOutAsync, sem UpdateSecurityStampAsync. Um cookie roubado continua válido até 30 min após o logout (CWE-613)	Média	AuthService.cs:170-185; ServiceCollectionExtensions.cs:81-82	AuthService	Atualizar o security stamp no logout
F-04 [C]	A API não tem antiforgery. O POST /api/documents/upload (multipart) e o POST /api/auth/logout aceitam POST de formulário e dependem só de SameSite=Strict. Isso não protege contra outra origem same-site, como outra porta em localhost (CWE-352)	Baixa/Média	DocumentsApiController.cs:73-85; AuthApiController.cs:57-63; ApiControllerBase.cs:10-12	API	Exigir header customizado ou token antiforgery; adicionar teste
F-05 [C]	Cookies com SecurePolicy.SameAsRequest. Não há HTTPS redirection nem HSTS, e o cookie antiforgery não é Secure	Baixa no lab, Alta se exposto	ServiceCollectionExtensions.cs:80,90-95; SecurityHeadersMiddleware.cs:29-35	Config	Condicionar a Always fora do modo lab
F-06 [C]	O seed vem ligado por padrão no Docker, com credenciais públicas (admin/Admin@123!), e não há trava por ambiente. A porta é só 127.0.0.1, o que mitiga	Média (mitigada)	docker-compose.yml:46; DatabaseInitializer.cs:39-43; README.md:241	Compose/Seed	Recusar o seed em Production sem flag explícita; banner de aviso
F-07 [C]	Enumeração de contas no cadastro: "Este nome de usuário/e-mail já está em uso"	Baixa	PortugueseIdentityErrorDescriber.cs:20-24; teste Register_WithDuplicateUserName_Returns400	Registro	É uma superfície de teste útil; documentar
F-08 [C]	Enumeração de IDs de documento: o sistema devolve 404 quando o ID não existe e 403 quando existe sem permissão. Os IDs são inteiros sequenciais. Para usuários o código está correto: a autorização vem antes da busca	Baixa	DocumentService.cs:55-65,157-167	DocumentService	Opcional: devolver 404 nos dois casos. O 403 auditado é útil para detecção
F-09 [C]	O username digitado em login falho é gravado em auditoria e log. Se o usuário digitar a senha nesse campo, ela é registrada (CWE-532). Os testes só cobrem o campo de senha	Baixa	AuthService.cs:70,77; AuditService.cs:53	Auditoria	Mascarar usernames fora do padrão; adicionar teste
F-10 [C]	Falhas de autorização sem auditoria: UnlockAsync negado, leituras bem-sucedidas do diretório de usuários e /admin/users. Falha de validação antiforgery (400) e tentativas repetidas de 404 só aparecem como HttpRequest	Baixa	UserService.cs:249-254,85-101	Auditoria	Padronizar com DenyAsync e criar eventos específicos
F-11 [P]	Enumeração de usuários por tempo de resposta: usuário inexistente ou inativo retorna sem calcular hash	Baixa	AuthService.cs:73-92	Login	Medir com 30+ amostras por caso
F-12 [P]	/error/{statusCode:int} é anônimo e aceita qualquer inteiro. Pode produzir resposta anômala ou exceção com valores fora de 100–999	Baixa	ErrorController.cs:23-33	Erros	Testar /error/0, /error/5000. Restringir o intervalo
F-13 [P]	Respostas autenticadas e downloads sem Cache-Control: no-store (não localizei). AllowedHosts: "*". X-Request-ID aceita qualquer valor com formato válido, o que permite forjar correlação nos logs	Info/Baixa	SecurityHeadersMiddleware.cs; appsettings.json:38; CorrelationMiddleware.cs:28	Config	Validar em runtime
F-14 [P]	Upload sem cota por usuário ou total. Arquivos .docx/.xlsx são validados só pelo magic number ZIP. Arquivo órfão se AddAsync falhar depois de SaveAsync	Baixa	LocalFileStorageService.cs:41-49,90-110; DocumentService.cs:128-143	Upload	Documentar. Candidato a módulo de laboratório
F-15 [P]	Imagem Docker sem HEALTHCHECK, read_only, cap_drop ou digest de imagem. Senha padrão do Postgres no compose. Em Development o DeveloperExceptionPage pode expor stack traces	Info	Dockerfile; docker-compose.yml:22; .env.example:11	Docker	Hardening opcional; manter Production como padrão
F-16 [D]	Oito arquivos referenciados não existem: docs/security/{permissions, security-baseline, extension-points, exercise-template}.md e docs/siem/{log-schema, event-catalog, detection-use-cases, integration-guide}.md. Também não há LICENSE nem SECURITY.md	Média (GitHub)	README.md:428-435; AppRoles.cs:5; Lab/README.md:6,24	Docs	Criar os documentos ou remover as referências
F-17 [C]	Sem recuperação de conta, MFA, confirmação de e-mail ou expiração absoluta de sessão (só sliding de 30 min)	Info (limitação)	ServiceCollectionExtensions.cs:63,81-82	Auth	Fora do escopo atual; módulo futuro
Sem evidência de falha:

IDOR em usuários e documentos.
Escalonamento vertical via DTO (o service devolve 403 e audita como High).
XSS refletido e armazenado.
Open redirect (IsLocalUrl).
Path traversal (regex ^[a-f0-9]{32}\.[a-z0-9]{1,10}$ mais StartsWith(_root + separador)).
Execução de upload (nome GUID, fora de wwwroot, attachment com nosniff).
Vazamento de hash ou stamp (UserDto não os expõe).
Pacotes NuGet: nenhum vulnerável nem depreciado segundo dotnet list package contra nuget.org.
C. OWASP Coverage
Categoria	Superfície	Controles verificados	Lacunas
Broken Access Control	/api/users/{id}, /api/documents/{id}, /admin/*	Fallback policy; AdminOnly; CanRead; checagem de self em UserService	F-08; sem teste do IDOR por ID sequencial
Authentication	/login, /api/auth/*	PBKDF2 do Identity; lockout 5x/15 min; mensagem genérica; revalidação do stamp a cada 1 min	F-02, F-03, F-11, F-17
Injection	Busca em documentos e usuários, filtros de auditoria	Só LINQ parametrizado	Nenhuma encontrada
XSS	Views Razor, site.js	Codificação do Razor; CSP sem inline; textContent	Nenhuma. Reflected/Stored/DOM só como alvo de módulo
CSRF	MVC e API	AutoValidateAntiforgeryToken no MVC; cookies Strict	F-04
SSRF	Nenhuma	Sem HttpClient	Sem superfície
File Upload	/documents/upload, /api/documents/upload	Allowlist, magic bytes, 5 MB, GUID, limite de 10 MB no request	F-14
Path Traversal	Download	Regex mais prefixo	Nenhuma
Mass Assignment	PUT de usuário, cadastro	DTOs explícitos; BindNever	Nenhuma
Misconfiguration	Headers, CORS, erros	CSP, XFO, nosniff, COOP; CORS não configurado (nega por padrão); ProblemDetails genérico	F-05, F-12, F-13, F-15
Sensitive Data	Logs e auditoria	SensitiveData mascara chaves sensíveis; LogSanitizer	F-09
Business Logic	Classificação de documentos, papéis	Regras em um só lugar; admin não rebaixa nem exclui a si mesmo	Sem fluxo multi-etapa para explorar
API Security	/api/*	401 e 403 em JSON; [ApiController]; limites de DTO	F-02, F-04, F-08
D. Laboratory Readiness
Pontos fortes para telemetria:

Log JSON com campos estáveis.
request_id ligando log técnico e auditoria.
Severidade por evento.
Auditoria de consulta à própria auditoria.
Arquivo security-*.json separado.
Trilha dupla: banco e arquivo.
Limitações:

Cobertura de eventos: faltam os de F-10 (negação de unlock, leitura do diretório, 404 repetidos e falha de antiforgery).
Imutabilidade: audit_events é editável pela aplicação e os logs não têm proteção de integridade.
Formato: o JSON é próprio, sem mapeamento ECS ou CEF.
Proxy: o IP de origem não considera ForwardedHeaders, o que importa se houver proxy reverso.
Reset: não há script nem endpoint para restaurar o estado inicial. Hoje é só docker compose down -v.
Módulos: a pasta Lab/ é só o contrato (ILabModule) e AvailableModules = []. Não há módulos implementados.
Sobre o Lab/:

O que já existe: a pasta tem boas bases: desligado por padrão, dupla ativação e log de aviso na inicialização.
O que falta:
Uma trava por ambiente. MapSecurityLab só consulta a flag e não recusa Production.
Dados e contas dedicados aos exercícios.
Reset por módulo.
Auditoria das interações do exercício.
Como as rotas se comportam: as rotas /lab/{id} passariam pela fallback policy (qualquer autenticado). Cada módulo precisaria declarar sua própria policy.
E. GitHub Readiness
Bloqueantes (devem ser corrigidos antes de publicar):

F-01. Sem Data/, nada funciona após o clone.
F-16. Documentos referenciados ausentes e falta de LICENSE e SECURITY.md. Inclua também um aviso destacado de "intencionalmente vulnerável no futuro, uso só em ambiente isolado".
Verificado e limpo:

Histórico: um único commit (5f071a3).
Sem .env, chaves, certificados, dumps nem logs versionados.
logs/ está vazio, só com .gitkeep e README.md.
Uploads não são versionados (data/ ignorado).
As únicas credenciais são as de laboratório, fictícias e declaradas como tal (compose, .env.example, appsettings.Development.json, README).
Pacotes sem vulnerabilidades conhecidas.
Recomendado: corrigir F-06 e F-05 antes de divulgar, para que ninguém suba o ambiente fora de loopback sem perceber.

F. Laboratory Expansion Roadmap
Arquitetura proposta. Cada módulo vive em Lab/Modules/<Id>/ e traz suas duas variantes de endpoint lado a lado:

/lab/<id>/vulnerable/...
/lab/<id>/secure/...
Ambas gravam na auditoria com o campo lab_module e variant.

Contexto comum:

Banco ou schema próprio (lab_*), com dados fictícios.
Contas dedicadas (lab.alice, lab.bob).
Policy LabParticipant mais o gate de ambiente.
POST /lab/_reset (somente ADMIN) para restaurar o estado inicial.
A aplicação recusa subir com SecurityLab:Enabled=true em Production.
Prioridade	Módulo	Complexidade	Ideia
1	LAB-01 IDOR/BOLA em documentos	Baixa	Variante vulnerável sem CanRead. Compare com o 403 auditado
1	LAB-02 Mass assignment em perfil	Baixa	Entidade bindada direto, aceitando role
1	LAB-03 Força bruta / spraying	Baixa	Login sem rate limit contra o endpoint com limite
2	LAB-04 XSS (refletido e armazenado)	Média	Campo com Html.Raw contra o encoding padrão. Ajusta a CSP para o exercício
2	LAB-05 Upload inseguro	Média	Sem validação de assinatura; nome original preservado
2	LAB-06 SQL injection	Média	Busca com SQL concatenado sobre dados lab_*
3	LAB-07 CSRF na API	Média	Fecha F-04 no modo seguro e deixa aberto no vulnerável
3	LAB-08 Sessão após logout	Média	Reproduz F-03 como exercício
3	LAB-09 SSRF	Alta	Endpoint de "importar por URL" com destino interno simulado
3	LAB-10 Path traversal	Alta	Download por nome de arquivo
G. Test Plan
Estado da suíte atual. São 94 métodos de teste, ou 188 casos com os Theory. Rodando localmente com DOTNET_ROLL_FORWARD=Major sob o .NET 10, 74 passaram e 114 falharam. A causa que consegui isolar é ambiental: The PipeWriter 'ResponseBodyPipeWriter' does not implement UnflushedBytes. É a incompatibilidade do TestServer 8.0 com o shared framework 10, e não um defeito da aplicação. Resultado: inconclusivo. Reexecute com o SDK 8 ou com docker compose --profile test run --rm tests.

Testes automatizados ausentes:

IDOR por ID sequencial em /api/documents/{id} e /api/users/{id}.
CSRF nos endpoints da API e nas ações MVC de admin (hoje só o login é testado).
DocumentAccessPolicy na borda: dono rebaixado, classificação inválida via JSON numérico.
Logout seguido de reuso do cookie (F-03).
Username malicioso no log (F-09), /error/{n} fora de intervalo (F-12).
Upload: polyglot ZIP, arquivo com extensão dupla, nome com Unicode ou ponto final.
Rate limiting, depois de implementado.
Isolamento do Lab/: com Enabled=true mas sem módulo na lista, nenhuma rota /lab/*; e recusa em Production.
Diferenças entre InMemory e PostgreSQL que afetam segurança:

Índices únicos e foreign keys não são impostos no InMemory, então corridas de cadastro e o ON DELETE SET NULL não são exercitados.
Limites de tamanho de coluna não são aplicados.
O requisito de DateTimeKind.Utc do Npgsql não é exercitado.
A tradução de ToLower().Contains e a collation diferem.
Recomendo uma suíte mínima com Testcontainers ou o Postgres do compose.
Validação manual local, não destrutiva. Rode apenas contra 127.0.0.1:8080 e com as contas de seed:

Endpoint	Classe	Papel	Procedimento	Esperado	Evidência nos logs
GET /api/documents/{id} com ID varrido de 1 a 15	IDOR / enumeração	employee	curl com cookie, comparar 200, 403 e 404	403 para Confidential e Restricted, 404 para IDs inexistentes	AccessDenied / document.read_denied, severidade Medium, mesmo request_id
PUT /api/users/{id} com {"role":"ADMIN"}	Privilege escalation	employee	Enviar o próprio ID e o de outro usuário	403	AccessDenied / user.privilege_change_denied, High
POST /api/auth/login repetido (6x)	Brute force	qualquer conta de seed	6 senhas erradas, depois a correta	Lockout após a 5ª; correta continua negada	UserLoginFailed x5, UserLockedOut High
POST /api/auth/logout, depois reutilizar o cookie salvo em /api/auth/me	Sessão (F-03)	employee	Salvar o cookie, fazer logout, reenviar	Esperado seguro: 401. Esperado hoje: 200	UserLogout seguido de requisição autenticada
POST /api/documents/upload com .exe, .html e arquivo com "MZ"	Upload	employee	Variar extensão e conteúdo	400	DocumentUploaded com success=false
Upload com filename="../../x.txt"	Path traversal	employee	Verificar o nome armazenado	Só o nome base; GUID em disco	DocumentUploaded, Details sem diretórios
POST /login sem token antiforgery	CSRF	anônimo	curl -d sem token	400	HttpRequest com status_code 400
GET /error/0, /error/5000	F-12	anônimo	Observar status e corpo	4xx/5xx controlado, sem exceção	ApplicationError se houver exceção
GET /api/admin/logs como analyst	BFLA	analyst	curl	403	AccessDenied, authorization.policy_denied
30 logins com usuário existente e 30 inexistente	Enumeração por tempo (F-11)	anônimo	Comparar medianas	Diferença estatisticamente nula	UserLoginFailed com Details distintos
Para as ferramentas (ZAP, Burp, ffuf, Nuclei): use contexto autenticado por cookie e limite a taxa. O ffuf contra /api/documents/FUZZ e /documents/FUZZ/download com IDs numéricos é suficiente. Lembre que, sem rate limiting (F-02), uma varredura agressiva gerará muito ruído nos logs e na tabela audit_events.

H. Final Verdict
NOT READY para publicação e uso a partir do repositório. Depois de corrigir F-01 e F-16, o projeto passa a READY WITH RESTRICTIONS.

Justificativa:

Hoje o repositório publicado não compila (F-01, confirmado por clone limpo). Isso é um impedimento objetivo.
A aplicação em si tem uma base de segurança bem implementada e verificada: autorização por recurso, DTOs explícitos, upload endurecido, auditoria com correlação e logs JSON.
As restrições a documentar são:
Uso só em 127.0.0.1 ou rede isolada.
Sem rate limit, HTTPS ou HSTS (F-02, F-05).
Sessão não invalidada no logout (F-03).
API sem antiforgery (F-04).
Seed público ligado por padrão (F-06).
Sem módulos de laboratório ainda.
Suíte de testes ainda não confirmada em ambiente com .NET 8.
Ordem sugerida de correção: F-01, F-16, F-06, F-03, F-02, F-04, F-10, F-09, depois a bateria de testes e o Lab/.

Não publiquei o relatório como página porque você não indicou outros leitores. Se quiser, publico como artifact para compartilhar com o time.