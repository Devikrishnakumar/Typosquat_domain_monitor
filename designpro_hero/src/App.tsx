import React, { useState } from 'react';
import { ArrowRight, ArrowUpRight, Menu, X } from 'lucide-react';
import { ShinyText } from './components/ShinyText';

export const App: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navLinks = [
    { label: 'Home', href: '#' },
    { label: 'About Us', href: '#about' },
    { label: 'Courses', href: '#courses' },
    { label: 'Instructors', href: '#instructors' },
    { label: 'Testimonials', href: '#testimonials' },
    { label: 'Blog', href: '#blog' },
  ];

  return (
    <div className="relative w-full h-screen bg-[#000000] text-white overflow-hidden font-sans select-none">
      {/* Background: Full-screen looping video background */}
      <video
        autoPlay
        loop
        muted
        playsInline
        className="absolute inset-0 w-full h-full object-cover z-0 pointer-events-none"
      >
        <source
          src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260328_105406_16f4600d-7a92-4292-b96e-b19156c7830a.mp4"
          type="video/mp4"
        />
      </video>

      {/* Subtle Dark Vignette & Ambient Overlay */}
      <div className="absolute inset-0 bg-black/35 z-[1] pointer-events-none" />

      {/* Main Content Layout Container */}
      <div className="relative z-10 w-full h-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col justify-between py-6 sm:py-8 lg:py-10">
        
        {/* Navigation Bar */}
        <header className="w-full flex items-center justify-between">
          {/* Logo: Circular design with white border (2px), containing smaller filled circle inside + text */}
          <a href="#" className="flex items-center gap-3 group">
            <div className="w-8 h-8 rounded-full border-2 border-white flex items-center justify-center transition-transform duration-300 group-hover:scale-105">
              <div className="w-2.5 h-2.5 rounded-full bg-white" />
            </div>
            <span className="text-white font-semibold text-lg sm:text-xl tracking-tight">
              DesignPro
            </span>
          </a>

          {/* Desktop Nav: Rounded pill container with gray-700 border */}
          <nav className="hidden lg:flex items-center gap-1 px-4 py-2 rounded-full border border-gray-700 bg-black/40 backdrop-blur-md">
            {navLinks.map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="px-3.5 py-1.5 text-sm text-white/80 hover:text-white transition-colors duration-200 font-normal"
              >
                {link.label}
              </a>
            ))}
            <a
              href="#contact"
              className="group flex items-center gap-1.5 pl-3.5 pr-2 py-1.5 text-sm text-white/80 hover:text-white transition-colors duration-200"
            >
              <span>Contact us</span>
              <ArrowUpRight className="w-4 h-4 transition-transform duration-200 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </a>
          </nav>

          {/* Mobile Hamburger Menu Toggle */}
          <div className="lg:hidden flex items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-full border border-gray-700 bg-black/50 text-white/80 hover:text-white focus:outline-none transition-colors"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </header>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <div className="lg:hidden absolute top-20 left-4 right-4 z-50 p-6 rounded-2xl border border-gray-700 bg-black/90 backdrop-blur-xl flex flex-col gap-4 animate-in fade-in slide-in-from-top-4 duration-200">
            {navLinks.map((link) => (
              <a
                key={link.label}
                href={link.href}
                onClick={() => setMobileMenuOpen(false)}
                className="text-white/80 hover:text-white text-base py-1 transition-colors"
              >
                {link.label}
              </a>
            ))}
            <a
              href="#contact"
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-between text-white/80 hover:text-white text-base py-1 border-t border-gray-800 pt-3"
            >
              <span>Contact us</span>
              <ArrowUpRight className="w-4 h-4" />
            </a>
          </div>
        )}

        {/* Top Section (below nav): Two-column layout on large screens, stacked on mobile */}
        <section className="w-full grid grid-cols-1 lg:grid-cols-12 gap-4 lg:gap-8 pt-4 sm:pt-6">
          <div className="lg:col-span-6">
            <p className="text-white/80 text-sm md:text-base leading-relaxed max-w-xl font-normal">
              We deliver transformative programs that empower emerging product designers with cutting-edge expertise and vision to thrive globally.
            </p>
          </div>
          <div className="lg:col-span-6 flex justify-start lg:justify-end">
            <p className="text-white/80 text-sm md:text-base font-normal tracking-tight lg:text-right">
              8000+ Talented Designers Launched !
            </p>
          </div>
        </section>

        {/* Hero Section (center): Main Heading + ShinyText + CTA */}
        <main className="w-full my-auto flex flex-col items-center justify-center text-center py-6 sm:py-10">
          {/* Small uppercase text above heading */}
          <div className="mb-3 sm:mb-5">
            <span className="text-white/80 text-xs md:text-sm tracking-tight uppercase font-medium">
              Seats for Next Program Opening Soon
            </span>
          </div>

          {/* Main Heading with Exact Specifications: Line height 0.85, tracking-tighter */}
          <h1 className="text-5xl sm:text-7xl md:text-8xl xl:text-9xl tracking-tighter leading-[0.85] font-medium mb-8 sm:mb-12">
            <span className="block text-white font-medium">
              Become
            </span>
            <span className="block">
              <ShinyText
                text="Product Leader."
                baseColor="#64CEFB"
                shineColor="#ffffff"
                speed={3}
                spread={100}
                className="font-medium"
              />
            </span>
          </h1>

          {/* CTA Button: Black background, hover: gray-900, rounded-full shape */}
          <a
            href="#apply"
            className="group inline-flex items-center gap-3 bg-black hover:bg-gray-900 border border-gray-800 text-white font-medium text-sm md:text-base rounded-full px-6 md:px-8 py-3 md:py-4 transition-all duration-300 shadow-2xl hover:border-gray-700"
          >
            <span>Apply for Next Enrollment</span>
            <ArrowRight className="w-4 h-4 md:w-5 md:h-5 transition-transform duration-300 group-hover:translate-x-1.5" />
          </a>
        </main>

        {/* Footer spacer for vertical centering balance */}
        <footer className="w-full py-2 flex items-center justify-between text-xs text-white/40">
          <span>&copy; {new Date().getFullYear()} DesignPro Inc. All rights reserved.</span>
          <span>Global Product Design Accelerator</span>
        </footer>

      </div>
    </div>
  );
};

export default App;
