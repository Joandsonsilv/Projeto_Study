import express, { type Request, type Response, type NextFunction } from "express";
import { randomBytes, createHash } from "node:crypto";
import path from "node:path";
import { db, byId, byEmail, publicUser, rows, run, transaction, initDatabase, type UsuarioRow } from "./database";
import { passwordHash, passwordMatches, passwordValid } from "./passwords";

type AuthRequest = Request & { user?: UsuarioRow; sessionHash?: string };
type CourseRow = { id: number; conteudo: string | Record<string, unknown>; students?: number; inscrito?: number };
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "64kb" }));
app.use("/api", (_req, res, next) => { res.set("Cache-Control", "no-store"); next(); });
const cookieName = "studyflow_session";
const sessionLifetime = 12 * 60 * 60 * 1000;
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const cookieOptions = { httpOnly: true, sameSite: "lax" as const, secure: process.env.COOKIE_SECURE === "1", path: "/" };
const fail = (res: Response, status: number, mensagem: string) => res.status(status).json({ mensagem });
const emailOf = (value: string) => value.trim().toLowerCase();
const validId = (value: unknown) => Number.isSafeInteger(Number(value)) && Number(value) > 0;
function validNameEmail(body: any) {
  return typeof body?.nome === "string" && body.nome.trim().length >= 2 &&
    body.nome.trim().length <= 120 && typeof body?.email === "string" &&
    body.email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email.trim());
}
const asyncRoute = (fn: (req: AuthRequest, res: Response) => Promise<unknown>) =>
  (req: AuthRequest, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res)).catch(next);
  };
app.use("/api", (req, res, next) => {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    if (!req.is("application/json")) return fail(res, 415, "Envie os dados como JSON.");
    const origin = req.get("origin");
    if (origin) {
      try { if (new URL(origin).host !== req.get("host")) return fail(res,403,"Origem não autorizada."); }
      catch { return fail(res,403,"Origem inválida."); }
    }
  }
  next();
});
const attempts = new Map<string,{count:number;until:number}>();
function limited(key: string, limit: number, duration: number) {
  const now = Date.now();
  if (attempts.size > 10000) attempts.forEach((v, k) => { if (v.until <= now) attempts.delete(k); });
  const prev = attempts.get(key);
  if (!prev || prev.until <= now) { attempts.set(key,{count:1,until:now+duration}); return false; }
  prev.count++;
  return prev.count > limit;
}
async function issueSession(res: Response, user: UsuarioRow) {
  await run("DELETE FROM sessoes WHERE expira_em < ?", [Date.now()]);
  const token = randomBytes(32).toString("hex");
  await run("INSERT INTO sessoes (token_hash,usuario_id,expira_em) VALUES (?,?,?)", [digest(token),user.id,Date.now()+sessionLifetime]);
  res.cookie(cookieName, token, {...cookieOptions, maxAge:sessionLifetime});
}
// Middleware em cadeia com next() após autenticação, usando helper específico.
function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  const wrapped = asyncRoute(async (r, response) => {
    const token = r.headers.cookie?.split(";").map(v => v.trim()).find(v=>v.startsWith(cookieName+"="))?.slice(cookieName.length+1);
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return fail(response,401,"Entre na sua conta para continuar.");
    const hash = digest(token);
    const [session] = await rows<{usuario_id:number}>("SELECT usuario_id FROM sessoes WHERE token_hash=? AND expira_em>? LIMIT 1",[hash,Date.now()]);
    const user = session ? await byId(session.usuario_id) : undefined;
    if (!user || !user.ativo) {
      response.clearCookie(cookieName,cookieOptions);
      return fail(response,401,"Sua sessão expirou. Entre novamente.");
    }
    r.user = user;
    r.sessionHash = hash;
    next();
  });
  wrapped(req,res,next);
}
function authorized(req: AuthRequest,res:Response,next:NextFunction) {
  if (req.user?.trocar_senha) return fail(res,403,"Altere sua senha temporária antes de continuar.");
  next();
}
function admin(req:AuthRequest,res:Response,next:NextFunction) {
  if (req.user?.papel !== "admin") return fail(res,403,"Área exclusiva para administradores.");
  next();
}
const duplicate = (err:unknown) => typeof err === "object" && err !== null && "code" in err && (err as {code:string}).code === "ER_DUP_ENTRY";

app.post("/api/auth/register",asyncRoute(async(req,res)=>{
  if (limited(`register:${req.ip}`,30,60*60*1000)) return fail(res,429,"Muitas tentativas de cadastro. Tente mais tarde.");
  if (!validNameEmail(req.body) || !passwordValid(req.body?.senha)) return fail(res,400,"Preencha nome, e-mail válido e senha de 10 a 128 caracteres.");
  const email=emailOf(req.body.email);
  if (await byEmail(email)) return fail(res,409,"Este e-mail já possui uma conta.");
  const {hash,salt}=await passwordHash(req.body.senha);
  try { await run("INSERT INTO usuarios(nome,email,senha_hash,senha_salt,papel) VALUES (?,?,?,?,'aluno')",[req.body.nome.trim(),email,hash,salt]); }
  catch(error){ if(duplicate(error)) return fail(res,409,"Este e-mail já possui uma conta."); throw error; }
  return res.status(201).json({mensagem:"Conta de aluno salva no MySQL. Entre para se inscrever no curso."});
}));
app.post("/api/auth/login",asyncRoute(async(req,res)=>{
  if(limited(`login:${req.ip}`,25,15*60*1000)) return fail(res,429,"Muitas tentativas. Aguarde 15 minutos.");
  if(typeof req.body?.email!=="string" || !passwordValid(req.body?.senha)) return fail(res,401,"E-mail ou senha inválidos.");
  const user=await byEmail(emailOf(req.body.email));
  const valid=await passwordMatches(req.body.senha,user?.senha_hash ?? "00".repeat(64),user?.senha_salt ?? "00".repeat(16));
  if(!user || !valid || !user.ativo) return fail(res,401,"E-mail ou senha inválidos.");
  await issueSession(res,user);
  return res.json({usuario:publicUser(user)});
}));
app.get("/api/auth/me",requireAuth,(req:AuthRequest,res)=>res.json({usuario:publicUser(req.user!)}));
app.post("/api/auth/logout",requireAuth,asyncRoute(async(req,res)=>{
  await run("DELETE FROM sessoes WHERE token_hash=?",[req.sessionHash!]);
  res.clearCookie(cookieName,cookieOptions);
  return res.json({mensagem:"Você saiu da conta."});
}));
app.post("/api/auth/password",requireAuth,asyncRoute(async(req,res)=>{
  if(limited(`password:${req.user!.id}`,10,15*60*1000)) return fail(res,429,"Aguarde antes de tentar novamente.");
  if(!passwordValid(req.body?.senhaAtual) || !passwordValid(req.body?.novaSenha)) return fail(res,400,"Use uma senha de 10 a 128 caracteres.");
  if(!(await passwordMatches(req.body.senhaAtual,req.user!.senha_hash,req.user!.senha_salt))) return fail(res,400,"Senha atual incorreta.");
  if(req.body.senhaAtual===req.body.novaSenha) return fail(res,400,"Escolha uma senha diferente.");
  const {hash,salt}=await passwordHash(req.body.novaSenha);
  await transaction(async c=>{
    await run("UPDATE usuarios SET senha_hash=?,senha_salt=?,trocar_senha=0 WHERE id=?",[hash,salt,req.user!.id],c);
    await run("DELETE FROM sessoes WHERE usuario_id=?",[req.user!.id],c);
  });
  const user=(await byId(req.user!.id))!;
  await issueSession(res,user);
  return res.json({mensagem:"Senha atualizada.",usuario:publicUser(user)});
}));

app.use("/api/usuarios",requireAuth,authorized,admin);
app.get("/api/usuarios",asyncRoute(async(_req,res)=>{
  const users=await rows<UsuarioRow>("SELECT * FROM usuarios ORDER BY criado_em DESC,id DESC");
  return res.json(users.map(publicUser));
}));
app.post("/api/usuarios",asyncRoute(async(req,res)=>{
  if(!validNameEmail(req.body) || !passwordValid(req.body?.senha) || !["admin","aluno"].includes(req.body?.papel)) return fail(res,400,"Preencha nome, e-mail, perfil e senha de 10 a 128 caracteres.");
  const email=emailOf(req.body.email);
  const {hash,salt}=await passwordHash(req.body.senha);
  try {
    const result=await run("INSERT INTO usuarios (nome,email,senha_hash,senha_salt,papel,trocar_senha) VALUES (?,?,?,?,?,1)",[req.body.nome.trim(),email,hash,salt,req.body.papel]);
    return res.status(201).json(publicUser((await byId(result.insertId))!));
  } catch(error){ if(duplicate(error)) return fail(res,409,"Este e-mail já está cadastrado."); throw error; }
}));
app.put("/api/usuarios/:id",asyncRoute(async(req,res)=>{
  if(!validId(req.params.id)) return fail(res,400,"Identificador inválido.");
  const id=Number(req.params.id);
  const old=await byId(id);
  if(!old) return fail(res,404,"Usuário não encontrado.");
  if(!validNameEmail(req.body) || !["admin","aluno"].includes(req.body?.papel) || typeof req.body?.ativo!=="boolean") return fail(res,400,"Confira nome, e-mail, perfil e situação.");
  if(req.body.senha && !passwordValid(req.body.senha)) return fail(res,400,"A senha temporária deve ter de 10 a 128 caracteres.");
  if(id===req.user!.id && (req.body.papel!=="admin" || !req.body.ativo || req.body.senha)) return fail(res,400,"Use Minha conta para a própria senha e mantenha seu acesso de ADM.");
  const password=req.body.senha ? await passwordHash(req.body.senha) : null;
  try {
    await transaction(async c=>{
      const [current]=(await rows<UsuarioRow>("SELECT * FROM usuarios WHERE id=? FOR UPDATE",[id],c));
      if(!current) throw new Error("NOT_FOUND");
      if(current.papel==="admin" && current.ativo && (req.body.papel!=="admin" || !req.body.ativo)) {
        const admins=await rows<{id:number}>("SELECT id FROM usuarios WHERE papel='admin' AND ativo=1 FOR UPDATE",[],c);
        if(admins.length<=1) throw new Error("LAST_ADMIN");
      }
      await run("UPDATE usuarios SET nome=?,email=?,papel=?,ativo=? WHERE id=?",[req.body.nome.trim(),emailOf(req.body.email),req.body.papel,req.body.ativo?1:0,id],c);
      if(password) await run("UPDATE usuarios SET senha_hash=?,senha_salt=?,trocar_senha=1 WHERE id=?",[password.hash,password.salt,id],c);
      if(password || !req.body.ativo || current.papel!==req.body.papel) await run("DELETE FROM sessoes WHERE usuario_id=?",[id],c);
    });
  } catch(error){ if(duplicate(error)) return fail(res,409,"E-mail já cadastrado."); throw error; }
  return res.json(publicUser((await byId(id))!));
}));
app.delete("/api/usuarios/:id",asyncRoute(async(req,res)=>{
  if(!validId(req.params.id)) return fail(res,400,"Identificador inválido.");
  const id=Number(req.params.id);
  if(id===req.user!.id) return fail(res,400,"Você não pode excluir sua própria conta administrativa.");
  await transaction(async c=>{
    const [user]=await rows<UsuarioRow>("SELECT * FROM usuarios WHERE id=? FOR UPDATE",[id],c);
    if(!user) throw new Error("NOT_FOUND");
    if(user.papel==="admin" && user.ativo) {
      const admins=await rows<{id:number}>("SELECT id FROM usuarios WHERE papel='admin' AND ativo=1 FOR UPDATE",[],c);
      if(admins.length<=1) throw new Error("LAST_ADMIN");
    }
    await run("DELETE FROM usuarios WHERE id=?",[id],c);
  });
  return res.json({mensagem:"Usuário excluído."});
}));

function parseCourse(row:CourseRow) {
  const original=typeof row.conteudo==="string"?JSON.parse(row.conteudo):row.conteudo;
  return {...original,id:Number(row.id),students:Number(row.students??0),inscrito:Boolean(row.inscrito)};
}
function validCourse(body:any):boolean {
  return typeof body?.title==="string" && body.title.trim().length>=2 && body.title.length<=120 &&
    typeof body?.category==="string" && body.category.trim().length>0 && body.category.length<=80 &&
    typeof body?.description==="string" && body.description.length<=2000;
}
const courseQuery = `SELECT c.id,c.conteudo,
  (SELECT COUNT(*) FROM matriculas m WHERE m.curso_id=c.id) AS students,
  EXISTS(SELECT 1 FROM matriculas m2 WHERE m2.curso_id=c.id AND m2.usuario_id=?) AS inscrito
  FROM cursos c WHERE c.ativo=1 ORDER BY c.id`;
app.use("/api/cursos",requireAuth,authorized);
app.get("/api/cursos",asyncRoute(async(req,res)=>{
  const courses=await rows<CourseRow>(courseQuery,[req.user!.id]);
  return res.json({cursos:courses.map(parseCourse)});
}));
app.post("/api/cursos",admin,asyncRoute(async(req,res)=>{
  if(!validCourse(req.body)) return fail(res,400,"Informe nome, categoria e descrição válidos.");
  const content={title:req.body.title.trim(),category:req.body.category.trim(),description:req.body.description.trim(),color:"violet",lessonsList:[],lessons:0,duration:"0h 00min",progress:0,students:0};
  const result=await run("INSERT INTO cursos (conteudo) VALUES (?)",[JSON.stringify(content)]);
  return res.status(201).json({curso:{...content,id:result.insertId,inscrito:false}});
}));
app.put("/api/cursos/:id",admin,asyncRoute(async(req,res)=>{
  if(!validId(req.params.id) || !validCourse(req.body)) return fail(res,400,"Confira os dados do curso.");
  const id=Number(req.params.id);
  const [old]=await rows<CourseRow>("SELECT id,conteudo FROM cursos WHERE id=? AND ativo=1",[id]);
  if(!old) return fail(res,404,"Curso não encontrado.");
  const content={...(typeof old.conteudo==="string"?JSON.parse(old.conteudo):old.conteudo),title:req.body.title.trim(),category:req.body.category.trim(),description:req.body.description.trim()};
  await run("UPDATE cursos SET conteudo=? WHERE id=?",[JSON.stringify(content),id]);
  const [count]=await rows<{total:number}>("SELECT COUNT(*) AS total FROM matriculas WHERE curso_id=?",[id]);
  return res.json({curso:{...content,id,students:Number(count.total),inscrito:false}});
}));
app.delete("/api/cursos/:id",admin,asyncRoute(async(req,res)=>{
  if(!validId(req.params.id)) return fail(res,400,"Identificador inválido.");
  const [existingCourses] = await rows<{total:number}>("SELECT COUNT(*) AS total FROM cursos WHERE ativo=1");
  if (Number(existingCourses.total) <= 1) return fail(res, 400, "Cadastre outro curso antes de remover o último.");
  const result=await run("UPDATE cursos SET ativo=0 WHERE id=? AND ativo=1",[Number(req.params.id)]);
  if(!result.affectedRows) return fail(res,404,"Curso não encontrado.");
  return res.json({mensagem:"Curso removido da listagem."});
}));
app.post("/api/cursos/:id/matriculas",asyncRoute(async(req,res)=>{
  if(req.user!.papel!=="aluno") return fail(res,403,"Para se inscrever, entre com uma conta de aluno.");
  if(!validId(req.params.id)) return fail(res,400,"Curso inválido.");
  const id=Number(req.params.id);
  const [course]=await rows<{id:number}>("SELECT id FROM cursos WHERE id=? AND ativo=1",[id]);
  if(!course) return fail(res,404,"Curso não encontrado.");
  const created=await run("INSERT IGNORE INTO matriculas (usuario_id,curso_id) VALUES (?,?)",[req.user!.id,id]);
  const [counter]=await rows<{total:number}>("SELECT COUNT(*) AS total FROM matriculas WHERE curso_id=?",[id]);
  return res.status(created.affectedRows?201:200).json({inscrito:true,jaInscrito:!created.affectedRows,students:Number(counter.total)});
}));

app.use("/api",(_req,res)=>fail(res,404,"Recurso não encontrado."));
app.use((error:Error,_req:Request,res:Response,_next:NextFunction)=>{
  if(error.message==="LAST_ADMIN") return fail(res,400,"Mantenha pelo menos um ADM ativo.");
  if(error.message==="NOT_FOUND") return fail(res,404,"Usuário não encontrado.");
  if(error instanceof SyntaxError) return fail(res,400,"JSON inválido.");
  console.error("Erro no servidor:",error);
  return fail(res,500,"Não foi possível concluir. Verifique o servidor e o banco MySQL.");
});
const publicPath=path.resolve("dist/public");
app.use(express.static(publicPath));
app.get("*",(_req,res)=>res.sendFile(path.join(publicPath,"index.html")));

try {
  await initDatabase();
  const port=Number(process.env.PORT||3001);
  const server=app.listen(port,()=>console.log(`Study Flow e API MySQL: http://localhost:${port}`));
  const shutdown=()=>server.close(()=>void db.end().then(()=>process.exit(0)));
  process.on("SIGTERM",shutdown);
  process.on("SIGINT",shutdown);
} catch(error) {
  console.error("MySQL não disponível. Leia GUIA-MAC-MYSQL.md:",error instanceof Error?error.message:error);
  await db.end();
  process.exitCode=1;
}
