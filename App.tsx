import { Route, Switch, Redirect } from "wouter";
import "./study-areas.css";
import "./auth.css";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import StudyArea from "./pages/StudyArea";
import Home from "./pages/Home";
import Login from "./pages/Login";
import CoursePage from "./pages/CoursePage";
import Users from "./pages/Users";
import Account from "./pages/Account";
import NotFound from "./pages/NotFound";

function Protected({
  children,
  admin = false,
  password = false,
}: {
  children: React.ReactNode;
  admin?: boolean;
  password?: boolean;
}) {
  const auth = useAuth();
  if (auth.loading)
    return <main className="auth-status">Verificando sua sessão…</main>;
  if (auth.error)
    return (
      <main className="auth-status">
        <p>{auth.error}</p>
        <button className="primary-btn" onClick={() => void auth.refresh()}>
          Tentar novamente
        </button>
      </main>
    );
  if (!auth.user) return <Redirect to="/login" />;
  if (auth.user.trocarSenha && !password) return <Redirect to="/minha-conta" />;
  if (admin && auth.user.papel !== "admin") return <Redirect to="/" />;
  return <div key={auth.user.id}>{children}</div>;
}
export default function App() {
  return (
    <AuthProvider>
      <Switch>
        <Route path="/login">
          <Login />
        </Route>
        <Route path="/admin/usuarios">
          <Protected admin>
            <Users />
          </Protected>
        </Route>
        <Route path="/minha-conta">
          <Protected password>
            <Account />
          </Protected>
        </Route>
        <Route path="/aulas">
          <Protected>
            <StudyArea key="aulas" view="aulas" />
          </Protected>
        </Route>
        <Route path="/exercicios">
          <Protected>
            <StudyArea key="exercicios" view="exercicios" />
          </Protected>
        </Route>
        <Route path="/progresso">
          <Protected>
            <StudyArea key="progresso" view="progresso" />
          </Protected>
        </Route>
        <Route path="/curso/:id">
          <Protected>
            <CoursePage />
          </Protected>
        </Route>
        <Route path="/">
          <Protected>
            <Home />
          </Protected>
        </Route>
        <Route>
          <NotFound />
        </Route>
      </Switch>
    </AuthProvider>
  );
}
