import paginationStyles from "./Pagination.module.css";
export function Pagination({ page, total, pageSize, setPage }: { page: number; total: number; pageSize: number; setPage: (n: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (pages <= 1) return null;
  return (
    <p className={`${paginationStyles.pagerRoot} pager`}>
      <button type="button" disabled={page <= 0} onClick={() => setPage(page - 1)}>Previous</button>{" "}
      Page {page + 1} of {pages} ({total} total){" "}
      <button type="button" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
    </p>
  );
}
