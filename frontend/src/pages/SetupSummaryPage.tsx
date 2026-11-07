import { useTranslation } from "react-i18next";
import { SetupSummary, type SetupSummaryData } from "@/components/SetupSummary.tsx";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";

export function SetupSummaryPage() {
  const { t } = useTranslation();
  const query = useGet<SetupSummaryData>("/api/setup/summary");
  return (
    <section>
      {query.loading && !query.data ? <p className="text-sm text-muted">{t("common.loading")}</p> : null}
      {query.error ? <p className="text-sm text-debian">{query.error}</p> : null}
      {query.data ? (
        <SetupSummary
          data={query.data}
          actions={
            <button
              type="button"
              onClick={query.reload}
              className={ui.button}
            >
              {t("common.refresh")}
            </button>
          }
        />
      ) : null}
    </section>
  );
}
