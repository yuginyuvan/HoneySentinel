import { BrowserRouter, Routes, Route } from "react-router-dom";

import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Attacks from "./pages/Attacks";
import Credentials from "./pages/Credentials";
import Commands from "./pages/Commands";
import AIAnalysis from "./pages/AIAnalysis";
import Settings from "./pages/Settings";

function App() {
  return (
    <BrowserRouter>

      <Routes>

        <Route 
          path="/" 
          element={<Login />} 
        />

        <Route 
          path="/dashboard" 
          element={<Dashboard />} 
        />

        <Route 
          path="/attacks" 
          element={<Attacks />} 
        />

        <Route 
          path="/credentials" 
          element={<Credentials />} 
        />

        <Route 
          path="/commands" 
          element={<Commands />} 
        />

        <Route 
          path="/ai" 
          element={<AIAnalysis />} 
        />

        <Route 
          path="/settings" 
          element={<Settings />} 
        />

      </Routes>

    </BrowserRouter>
  );
}

export default App;