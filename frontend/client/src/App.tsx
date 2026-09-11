/* Graphite Signal Console: real route-backed views, persistent layout shell, explicit local boundaries. */
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import Layout from "./components/Layout";
import { ThemeProvider } from "./contexts/ThemeContext";
import { CapabilityProvider } from "./contexts/CapabilityContext";
import Home from "./pages/Home";
import AssuranceDashboard from "./pages/AssuranceDashboard";
import WebsiteSecurityPage from "./pages/WebsiteSecurityPage";

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
import PrivacyPolicy from "./pages/PrivacyPolicy";
import TermsAndConditions from "./pages/TermsAndConditions";
import PolicyPage from "./pages/PolicyPage";
import PrimaryWorkflowPage from "./pages/PrimaryWorkflowPage";

function Router() {
  return (
    <Layout>
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/audits"><PrimaryWorkflowPage kind="audits" /></Route>
        <Route path="/inventory"><PrimaryWorkflowPage kind="inventory" /></Route>
        <Route path="/monitoring"><PrimaryWorkflowPage kind="monitoring" /></Route>
        <Route path="/drift"><PrimaryWorkflowPage kind="drift" /></Route>
        <Route path="/review-queue"><PrimaryWorkflowPage kind="review" /></Route>
        <Route path="/control-packs"><PrimaryWorkflowPage kind="controls" /></Route>
        <Route path="/remediation"><PrimaryWorkflowPage kind="remediation" /></Route>
        <Route path="/settings"><PrimaryWorkflowPage kind="settings" /></Route>
        <Route path="/operator-guide"><PrimaryWorkflowPage kind="guide" /></Route>
        <Route path="/website-security" component={WebsiteSecurityPage} />
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

        {/* Legal Pages */}
        <Route path="/privacy" component={PrivacyPolicy} />
        <Route path="/terms" component={TermsAndConditions} />
        <Route path="/policy" component={PolicyPage} />

        <Route path="/404" component={NotFound} />
        <Route component={NotFound} />
      </Switch>
    </Layout>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <CapabilityProvider>
        <ThemeProvider defaultTheme="light" switchable>
          <TooltipProvider>
            <Toaster />
            <Router />
          </TooltipProvider>
        </ThemeProvider>
      </CapabilityProvider>
    </ErrorBoundary>
  );
}
