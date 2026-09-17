import { createFileRoute, Link } from '@tanstack/react-router';
import { HomeLayout } from 'fumadocs-ui/layouts/home';
import { baseOptions } from '@/lib/layout.shared';

export const Route = createFileRoute('/')({
  component: Home,
});

function Home() {
  return (
    <HomeLayout {...baseOptions()}>
      <div className="flex flex-col flex-1 justify-center px-4 py-20">
        <div className="mx-auto w-full max-w-2xl">
          <p className="font-mono text-xs tracking-widest text-fd-muted-foreground uppercase mb-6">
            go · huma · bun · postgres
          </p>
          <h1 className="fd-display font-sans text-5xl md:text-6xl font-medium tracking-tight mb-6">
            Brick
          </h1>
          <p className="text-fd-muted-foreground text-base mb-10 max-w-xl">
            Opinionated Go framework for CRUD APIs — typed resources on Huma +
            Bun + Postgres, with YAML DSL, deterministic codegen, guards,
            hooks, and validation built in.
          </p>
          <div className="flex flex-wrap items-center gap-3 mb-12">
            <Link
              to="/docs/$"
              params={{
                _splat: '',
              }}
              className="px-5 py-2.5 bg-fd-primary text-fd-primary-foreground font-medium text-sm"
            >
              Open Docs
            </Link>
            <Link
              to="/docs/$"
              params={{
                _splat: 'quickstart',
              }}
              className="px-5 py-2.5 border border-fd-border text-fd-foreground font-medium text-sm hover:bg-fd-muted transition-colors"
            >
              Quickstart
            </Link>
          </div>
          <div className="border border-fd-border bg-fd-card">
            <div className="border-b border-fd-border px-4 py-2 font-mono text-xs text-fd-muted-foreground">
              quickstart.go
            </div>
            <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed">
              <code>
                <span className="text-fd-muted-foreground">{'// one resource, full CRUD'}</span>
                {'\n'}
                deal := brick.Resource(<span className="text-fd-primary">"deal"</span>,{' '}
                <span className="text-fd-primary">"deals"</span>, dealSchema)
                {'\n'}
                b, _ := brick.New(cfg)
                {'\n'}
                http.ListenAndServe(<span className="text-fd-primary">":8080"</span>,
                b.Handler())
              </code>
            </pre>
          </div>
        </div>
      </div>
    </HomeLayout>
  );
}
