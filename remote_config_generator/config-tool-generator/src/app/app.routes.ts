import { Routes } from '@angular/router';

import { LayoutComponent } from './shared/components/layout/layout.component';

const title = 'Config-Tool-Generator |';

export const routes: Routes = [
	{
		path: '',
		redirectTo: '/home',
		pathMatch: 'full'
	},
	{
		path: '',
		component: LayoutComponent,
		children: [
			{
				path: '',
				redirectTo: 'home',
				pathMatch: 'full'
			},
			{
				path: 'home',
				loadComponent: () => import('@pages/home/home.component'),
				title: `${title} Home`
			}
		]
	},
	{
		path: 'page-not-found',
    loadComponent: () => import('@shared/components/page-not-found/page-not-found.component'),
		title: `${title} Page Not Found`
	},
	{ path: '**', redirectTo: '/page-not-found' }
];


