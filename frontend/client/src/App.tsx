/* Graphite Signal Console: real route-backed views, explicit local boundaries, accessible theme switching. */
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import AssuranceDashboard from "./pages/AssuranceDashboard";

import BlastRadiusPage from "./pages/BlastRadiusPage";
import FreshnessPage from "./pages/FreshnessPage";
import TimelinePage from "./pages/TimelinePage";
import NotaryPage from "./pages/NotaryPage";
import MutationLabPage from "./pages/MutationLabPage";
import ParserDiffPage from "./pages/ParserDiffPage";
import AttackGraphPage from "./pages/AttackGraphPage";
import CounterfactualPage from "./pages/CounterfactualPage";
import DecisionQualityPage from "./pages/DecisionQualityPage";
import SecretsGatePage from "./pages/SecretsGatePage";
import SupplyChainPage from "./pages/SupplyChainPage";
import ProvenancePage from "./pages/ProvenancePage";
import ThreatModelPage from "./pages/ThreatModelPage";
import ApiContractPage from "./pages/ApiContractPage";
import ResiliencePage from "./pages/ResiliencePage";
import DebtPage from "./pages/DebtPage";
import ExchangePage from "./pages/ExchangePage";
import RegulatoryPage from "./pages/RegulatoryPage";
import KnowledgeGraphPage from "./pages/KnowledgeGraphPage";

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
      
      {/* 20-Feature Portfolio Routes */}
      <Route path="/blast-radius" component={BlastRadiusPage} />
      <Route path="/freshness" component={FreshnessPage} />
      <Route path="/timeline" component={TimelinePage} />
      <Route path="/notary" component={NotaryPage} />
      <Route path="/mutation-lab" component={MutationLabPage} />
      <Route path="/parser-diff" component={ParserDiffPage} />
      <Route path="/graph" component={AttackGraphPage} />
      <Route path="/counterfactual" component={CounterfactualPage} />
      <Route path="/decision-quality" component={DecisionQualityPage} />
      <Route path="/secrets-gate" component={SecretsGatePage} />
      <Route path="/supply-chain" component={SupplyChainPage} />
      <Route path="/provenance" component={ProvenancePage} />
      <Route path="/threat-model" component={ThreatModelPage} />
      <Route path="/api-contract" component={ApiContractPage} />
      <Route path="/resilience" component={ResiliencePage} />
      <Route path="/debt" component={DebtPage} />
      <Route path="/exchange" component={ExchangePage} />
      <Route path="/regulatory" component={RegulatoryPage} />
      <Route path="/knowledge-graph" component={KnowledgeGraphPage} />

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
