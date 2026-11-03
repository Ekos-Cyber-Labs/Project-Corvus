import skeletonStyles from "./Skeleton.module.css";
export function Skeleton() {
  return <div className={`${skeletonStyles.skeletonRoot} skeleton`} aria-hidden="true"><span /><span /><span /></div>;
}
