import "dotenv/config";
import mysql, { type PoolConnection, type RowDataPacket, type ResultSetHeader } from "mysql2/promise";
import { readFile } from "node:fs/promises";
import path from "node:path";

export type Papel = "admin" | "aluno";
export type UsuarioRow = {
  id: number;
  nome: string;
  email: string;
  senha_hash: string;
  senha_salt: string;
  papel: Papel;
  ativo: number;
  trocar_senha: number;
  criado_em: string | Date;
};

if (!process.env.DB_NAME || !process.env.DB_USER) {
  throw new Error("Configure DB_NAME e DB_USER no arquivo .env. Consulte GUIA-MAC-MYSQL.md.");
}

export const db = mysql.createPool({
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  timezone: "Z",
  decimalNumbers: true,
  supportBigNumbers: true,
  bigNumberStrings: false,
});

export async function rows<T>(sql: string, params: unknown[] = [], connection: typeof db | PoolConnection = db): Promise<T[]> {
  const [result] = await connection.execute<RowDataPacket[]>(sql, params);
  return result as unknown as T[];
}

export async function run(sql: string, params: unknown[] = [], connection: typeof db | PoolConnection = db): Promise<ResultSetHeader> {
  const [result] = await connection.execute<ResultSetHeader>(sql, params);
  return result;
}

export async function transaction<T>(fn: (connection: PoolConnection) => Promise<T>): Promise<T> {
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const value = await fn(connection);
    await connection.commit();
    return value;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

export function publicUser(row: UsuarioRow) {
  return {
    id: Number(row.id),
    nome: row.nome,
    email: row.email,
    papel: row.papel,
    ativo: Boolean(row.ativo),
    trocarSenha: Boolean(row.trocar_senha),
    criadoEm: new Date(row.criado_em).toISOString(),
  };
}

export async function byId(id: number, connection: typeof db | PoolConnection = db) {
  const result = await rows<UsuarioRow>("SELECT * FROM usuarios WHERE id=? LIMIT 1", [id], connection);
  return result[0];
}
export async function byEmail(email: string, connection: typeof db | PoolConnection = db) {
  const result = await rows<UsuarioRow>("SELECT * FROM usuarios WHERE email=? LIMIT 1", [email], connection);
  return result[0];
}

// Mantém as três aulas/cursos originais em MySQL e não substitui alterações de ADM.
export async function initDatabase() {
  const sql = await readFile(path.resolve("database/schema.sql"), "utf8");
  for (const statement of sql.split(";").map(v => v.trim()).filter(Boolean)) {
    // Retira linhas de comentário; o arquivo contém apenas comandos DDL simples.
    const cleaned = statement.split("\n").filter(line => !line.trim().startsWith("--")).join("\n").trim();
    if (cleaned) await db.query(cleaned);
  }
  const initialCourses = JSON.parse(await readFile(path.resolve("client/src/data/courses.json"), "utf8")) as Array<{id:number}>;
  for (const course of initialCourses) {
    await run("INSERT IGNORE INTO cursos (id,conteudo) VALUES (?,?)", [course.id, JSON.stringify(course)]);
  }
}
