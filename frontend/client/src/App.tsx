/* Graphite Signal Console: real route-backed views, explicit local boundaries, accessible theme switching. */
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import AssuranceDashboard from "./pages/AssuranceDashboard";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/audits" component={Home} />
      <Route path="/inventory" component={Home} />
      <Route path="/monitoring" component={Home} />
      <Route path="/drift" component={Home} />
      <Route path="/review-queue" component={Home} />
      <Route path="/control-packs" component={Home} />
      <Route path="/remediation" component={Home} />
      <Route path="/settings" component={Home} />
      <Route path="/operator-guide" component={Home} />
      <Route path="/website-security" component={Home} />
      <Route path="/assurance-chain" component={AssuranceDashboard} />
      <Route path="/404" component={NotFound} />
      <Route component={NotFound} />
    </Switch>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="light" switchable>
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}
