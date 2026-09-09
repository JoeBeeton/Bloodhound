import { useEffect, useSyncExternalStore } from "react";
import * as bridge from "./authBridge";

export function useAuth() {
  const state = useSyncExternalStore(bridge.subscribe, bridge.getState);

  useEffect(() => {
    if (state.status === "loading") {
      bridge.bootstrap();
    }
  }, [state.status]);

  return {
    ...state,
    login: bridge.login,
    logout: bridge.logout,
    completeSsoLogin: bridge.completeSsoLogin,
    dismissSecurityBanner: bridge.dismissSecurityBanner,
  };
}
